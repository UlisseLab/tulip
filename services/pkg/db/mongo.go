// SPDX-FileCopyrightText: 2022 Qyn <qyn-ctf@gmail.com>
// SPDX-FileCopyrightText: 2022 Rick de Jager <rickdejager99@gmail.com>
// SPDX-FileCopyrightText: 2023 - 2024 gfelber <34159565+gfelber@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 Max Groot <19346100+MaxGroot@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 liskaant <50048810+liskaant@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 liskaant <liskaant@gmail.com>
// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package db

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type MongoDatabase struct {
	client *mongo.Client
}

// GetFlowList implements filtering logic similar to the Python getFlowList
func (db MongoDatabase) GetFlowList(filters bson.D) ([]FlowEntry, error) {
	collection := db.client.Database("pcap").Collection("pcap")

	opt := options.Find().
		SetLimit(0).                     // No limit, we want all matching flows
		SetSort(bson.M{"time": -1}).     // Sort by time descending
		SetProjection(bson.M{"flow": 0}) // Exclude flow details for performance

	// If filters are nil, use an empty filter
	if filters == nil {
		filters = bson.D{}
	}

	cur, err := collection.Find(context.TODO(), filters, opt)
	if err != nil {
		return nil, fmt.Errorf("failed to find flows: %v", err)
	}
	// Ensure the cursor is closed after use
	defer cur.Close(context.TODO())

	results := make([]FlowEntry, 0)
	for cur.Next(context.TODO()) {
		var entry FlowEntry
		err := cur.Decode(&entry)
		if err != nil {
			slog.Error("Failed to decode flow entry", "error", err)
			continue // Skip this entry if decoding fails
		}
		results = append(results, entry)
	}

	return results, nil
}

// GetTagList returns all tag names (_id) from the tags collection
func (db MongoDatabase) GetTagList() ([]string, error) {
	tagsCollection := db.client.Database("pcap").Collection("tags")

	cur, err := tagsCollection.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to find tags: %v", err)
	}

	defer cur.Close(context.TODO())

	tags := make([]string, 0)
	for cur.Next(context.TODO()) {
		var tag struct {
			ID string `bson:"_id"`
		}
		if err := cur.Decode(&tag); err == nil {
			tags = append(tags, tag.ID)
		}
	}

	pipeline := mongo.Pipeline{
		{{Key: "$unwind", Value: "$tags"}},
		{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: nil},
			{Key: "uniqueTags", Value: bson.D{{Key: "$addToSet", Value: "$tags"}}},
		}}},
		{{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "uniqueTags", Value: 1},
		}}},
	}

	flowCollection := db.client.Database("pcap").Collection("pcap")
	cur2, err := flowCollection.Aggregate(context.TODO(), pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate tags: %v", err)
	}
	defer cur2.Close(context.TODO())

	var aggResult []struct {
		UniqueTags []string `bson:"uniqueTags"`
	}
	if err := cur2.All(context.TODO(), &aggResult); err != nil {
		return nil, fmt.Errorf("failed to decode aggregation result: %v", err)
	}

	// Add unique tags from aggregation result
	if len(aggResult) != 0 {
		for _, tag := range aggResult[0].UniqueTags {
			if !slices.Contains(tags, tag) {
				tags = append(tags, tag)
			}
		}
	}

	return tags, nil
}

// CountFlows returns the number of flows matching the given filters.
func (db MongoDatabase) CountFlows(filters bson.D) (int, error) {
	collection := db.client.Database("pcap").Collection("pcap")
	count, err := collection.CountDocuments(context.TODO(), filters)
	return int(count), err
}

// GetSignature returns a signature document by its integer ID or ObjectID string
func (db MongoDatabase) GetSignature(id string) (Signature, error) {
	collection := db.client.Database("pcap").Collection("signatures")
	var result Signature

	// Try as ObjectID first
	objID, err := primitive.ObjectIDFromHex(id)

	filter := bson.M{"_id": objID}
	if err != nil {
		// Try as int
		intID, err2 := toInt(id)
		if err2 != nil {
			return result, fmt.Errorf("invalid id: %v", id)
		}
		filter = bson.M{"id": intID}
	}

	err = collection.FindOne(context.TODO(), filter).Decode(&result)
	return result, err
}

// SetStar sets or unsets the "starred" tag on a flow
func (db MongoDatabase) SetStar(flowID string, star bool) error {
	collection := db.client.Database("pcap").Collection("pcap")
	objID, err := primitive.ObjectIDFromHex(flowID)
	if err != nil {
		return err
	}
	update := bson.M{}
	if star {
		update = bson.M{"$push": bson.M{"tags": "starred"}}
	} else {
		update = bson.M{"$pull": bson.M{"tags": "starred"}}
	}
	_, err = collection.UpdateOne(context.TODO(), bson.M{"_id": objID}, update)
	return err
}

// GetFlowDetail returns a flow by its ObjectID string, including signatures
func (db MongoDatabase) GetFlowDetail(id string) (*FlowEntry, error) {
	collection := db.client.Database("pcap").Collection("pcap")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}
	var flow FlowEntry
	if err := collection.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&flow); err != nil {
		return nil, err
	}

	// Attach signatures if present (unchanged)
	if len(flow.Suricata) > 0 {
		sigColl := db.client.Database("pcap").Collection("signatures")
		var sigs []Signature
		for _, sigID := range flow.Suricata {
			var sig Signature
			err := sigColl.FindOne(context.TODO(), bson.M{"id": sigID}).Decode(&sig)
			if err == nil {
				sigs = append(sigs, sig)
			}
		}
		// Optionally, you can add a Signatures field to FlowEntry to hold these
		// For now, just ignore if not present in struct
	}

	return &flow, nil
}

// --- helpers for filter conversion ---
func toInt(v any) (int, error) {
	switch t := v.(type) {
	case int:
		return t, nil
	case int32:
		return int(t), nil
	case int64:
		return int(t), nil
	case float64:
		return int(t), nil
	case string:
		return strconv.Atoi(t)
	default:
		return 0, fmt.Errorf("not an int: %v", v)
	}
}

func ConnectMongo(uri string) (MongoDatabase, error) {
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(uri))
	if err != nil {
		return MongoDatabase{}, fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	if err := client.Ping(context.TODO(), readpref.Primary()); err != nil {
		client.Disconnect(context.TODO())
		return MongoDatabase{}, fmt.Errorf("failed to ping MongoDB: %v", err)
	}

	return MongoDatabase{
		client: client,
	}, nil
}

func (db MongoDatabase) ConfigureDatabase() {
	db.InsertTag("flag-in")
	db.InsertTag("flag-out")
	db.InsertTag("blocked")
	db.InsertTag("suricata")
	db.InsertTag("starred")
	db.InsertTag("flagid")
	db.InsertTag("tcp")
	db.InsertTag("udp")
	db.ConfigureIndexes()
}

func (db MongoDatabase) ConfigureIndexes() {
	// create Index
	flowCollection := db.client.Database("pcap").Collection("pcap")

	_, err := flowCollection.Indexes().CreateMany(context.Background(), []mongo.IndexModel{
		// time index (range filtering)
		{Keys: bson.D{{Key: "time", Value: 1}}},
		// data index (context filtering)
		{Keys: bson.D{{Key: "data", Value: "text"}}},
		// port combo index (traffic correlation)
		{Keys: bson.D{{Key: "src_port", Value: 1}, {Key: "dst_port", Value: 1}}},
	})

	if err != nil {
		fmt.Println("Error creating indexes:", err)
		panic(err)
	}
}

// Flows are either coming from a file, in which case we'll dedupe them by pcap file name.
// If they're coming from a live capture, we can do pretty much the same thing, but we'll
// just have to come up with a label. (e.g. capture-<epoch>)
// We can always swap this out with something better, but this is how flower currently handles deduping.
//
// A single flow is defined by a db.FlowEntry" struct, containing an array of flowitems and some metadata
func (db MongoDatabase) InsertFlow(flow FlowEntry) {
	flowCollection := db.client.Database("pcap").Collection("pcap")

	// Process the data, so it works well in mongodb
	for idx := range flow.Flow {
		flowItem := &flow.Flow[idx]

		flowItem.Raw = []byte(flowItem.Data)

		// filter the data string down to only printable characters
		newRaw := make([]byte, 0, len(flowItem.Data))
		for i := 0; i < len(flowItem.Data); i++ {
			if flowItem.Data[i] >= 32 && flowItem.Data[i] <= 126 {
				newRaw = append(newRaw, flowItem.Data[i])
			}
		}
		flowItem.Raw = newRaw
	}

	if len(flow.Fingerprints) > 0 {
		query := bson.M{
			"fingerprints": bson.M{
				"$in": flow.Fingerprints,
			},
		}
		opts := options.FindOne().SetSort(bson.M{"time": -1})

		type connectedFlow struct {
			MongoID primitive.ObjectID `bson:"_id"`
		}

		// TODO does this return the first one? If multiple documents satisfy the given query expression, then this method will return the first document according to the natural order which reflects the order of documents on the disk.
		connFlow := connectedFlow{}
		err := flowCollection.FindOne(context.TODO(), query, opts).Decode(&connFlow)

		// There is a connected flow
		if err == nil {
			//TODO Maybe add the childs fingerprints to mine?
			flow.ChildId = connFlow.MongoID
		}
	}

	// TODO; use insertMany instead
	insertion, err := flowCollection.InsertOne(context.TODO(), flow)
	if err != nil {
		log.Println("Error occured while inserting record: ", err)
		log.Println("NO PCAP DATA WILL BE AVAILABLE FOR: ", flow.Filename)
	}

	if flow.ChildId == primitive.NilObjectID {
		return
	}

	query := bson.M{"_id": flow.ChildId}

	info := bson.M{"$set": bson.M{"parent_id": insertion.InsertedID}}

	_, err = flowCollection.UpdateOne(context.TODO(), query, info)
	//TODO error handling
	if err != nil {
		log.Println("Error occured while updating record: ", err)
	}
}

type PcapFile struct {
	FileName string `bson:"file_name"` // Name of the pcap file
	Position int64  `bson:"position"`  // N. of packets processed so far
	Finished bool   `bson:"finished"`  // Indicates if the pcap file has been fully processed
}

// Insert a new pcap uri, returns true if the pcap was not present yet,
// otherwise returns false
func (db MongoDatabase) InsertPcap(pcap PcapFile) bool {
	files := db.client.Database("pcap").Collection("filesImported")

	// it could already be present, so let's update it
	filter := bson.M{"file_name": pcap.FileName}

	_, err := files.ReplaceOne(context.TODO(), filter, pcap, options.Replace().SetUpsert(true))
	if err != nil {
		log.Println("Error occured while inserting pcap file: ", err)
		return false
	}
	return true
}

func (db MongoDatabase) GetPcap(uri string) (bool, PcapFile) {
	files := db.client.Database("pcap").Collection("filesImported")
	var result PcapFile
	match := files.FindOne(context.TODO(), bson.M{"file_name": uri})
	match.Decode(&result)
	return match.Err() != mongo.ErrNoDocuments, result
}

type FlowID struct {
	Src_port int
	Dst_port int
	Src_ip   string
	Dst_ip   string
	Time     time.Time
}

type Signature struct {
	MongoID primitive.ObjectID `bson:"_id,omitempty"`
	ID      int
	Msg     string
	Action  string
	Tag     string `bson:"omitempty"`
}

func (db MongoDatabase) AddSignature(sig Signature) string {
	sigCollection := db.client.Database("pcap").Collection("signatures")

	// TODO; there's a bit of a race here, but I'm also racing to get this code working in time
	// for the next demo, so it all evens out.

	query := bson.M{
		"id":     sig.ID,
		"msg":    sig.Msg,
		"action": sig.Action,
		"tag":    sig.Tag,
	}

	var existing_sig Signature
	err := sigCollection.FindOne(context.TODO(), query).Decode(&existing_sig)
	if err != nil {
		// The signature does not appear in the DB yet. Let's add it.
		res, err := sigCollection.InsertOne(context.TODO(), query)
		if err != nil {
			log.Println("Rule add failed with error: ", err)
			return ""
		}
		ret := res.InsertedID.(primitive.ObjectID)
		return ret.Hex()
	} else {
		// The signature _does_ appear in the db. Let's return it's ID directly!
		return existing_sig.MongoID.Hex()
	}
}

func (db MongoDatabase) findFlowInDB(flow FlowID, window int) (mongo.Collection, bson.M) {
	// Find a flow that more or less matches the one we're looking for
	flowCollection := db.client.Database("pcap").Collection("pcap")
	epoch := int(flow.Time.UnixNano() / 1000000)
	filter := bson.M{
		"src_port": flow.Src_port,
		"dst_port": flow.Dst_port,
		"src_ip":   flow.Src_ip,
		"dst_ip":   flow.Dst_ip,
		"time": bson.M{
			"$gt": epoch - window,
			"$lt": epoch + window,
		},
	}

	return *flowCollection, filter
}

func (db MongoDatabase) updateFlowInDB(flowCollection mongo.Collection, filter bson.M, update bson.M) bool {
	// Enrich the flow with tag information
	res, err := flowCollection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		log.Println("Error occured while editing record:", err)
		return false
	}

	return res.MatchedCount > 0
}

func (db MongoDatabase) AddSignatureToFlow(flow FlowID, sig Signature, window int) bool {
	// Add the signature to the collection
	sig_id := db.AddSignature(sig)
	if sig_id == "" {
		return false
	}

	tags := []string{"suricata"}
	flowCollection, filter := db.findFlowInDB(flow, window)

	// Add tag from the signature if it contained one
	if sig.Tag != "" {
		db.InsertTag(sig.Tag)
		tags = append(tags, sig.Tag)
	}

	var update bson.M
	// TODO; This can probably be done more elegantly, right?
	if sig.Action == "blocked" {
		update = bson.M{
			"$set": bson.M{
				"blocked": true,
			},
			"$addToSet": bson.M{
				"tags": bson.M{
					"$each": append(tags, "blocked"),
				},
				"suricata": sig_id,
			},
		}
	} else {
		update = bson.M{
			"$addToSet": bson.M{
				"tags": bson.M{
					"$each": tags,
				},
				"suricata": sig_id,
			},
		}
	}

	return db.updateFlowInDB(flowCollection, filter, update)
}

func (db MongoDatabase) AddTagsToFlow(flow FlowID, tags []string, window int) bool {
	flowCollection, filter := db.findFlowInDB(flow, window)

	// Add tags to tag collection
	for _, tag := range tags {
		db.InsertTag(tag)
	}

	// Update this flow with the tags
	update := bson.M{
		"$addToSet": bson.M{
			"tags": bson.M{
				"$each": tags,
			},
		},
	}

	// Apply update to database
	return db.updateFlowInDB(flowCollection, filter, update)

}
func (db MongoDatabase) InsertTag(tag string) {
	tagCollection := db.client.Database("pcap").Collection("tags")
	// Yeah this will err... A lot.... Two more dev days till Athens, this will do.
	tagCollection.InsertOne(context.TODO(), bson.M{"_id": tag})
}

type Flagid struct {
	ID   primitive.ObjectID `bson:"_id"`
	Time int                `bson:"time"`
}

func (db MongoDatabase) GetFlagids(flaglifetime int) ([]Flagid, error) {
	// Create a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Access the "pcap" database and "flagids" collection
	collection := db.client.Database("pcap").Collection("flagids")

	// Find all documents in the
	var filter bson.M
	if flaglifetime < 0 {
		filter = bson.M{}
	} else {
		filter = bson.M{"time": bson.M{"$gt": int(time.Now().Unix()) - flaglifetime}}
	}

	cur, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to find flagids: %v", err)
	}
	defer func() {
		err := cur.Close(ctx)
		if err != nil {
			log.Printf("Failed to close cursor: %v", err)
		}
	}()

	var flagids []Flagid

	// Iterate through the cursor and extract _id values
	for cur.Next(ctx) {
		var flagid Flagid
		if err := cur.Decode(&flagid); err != nil {
			return nil, fmt.Errorf("failed to decode flagid: %v", err)
		}
		flagids = append(flagids, flagid)
	}

	if err := cur.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %v", err)
	}

	return flagids, nil

}

func (db MongoDatabase) GetLastFlows(ctx context.Context, limit int) ([]FlowEntry, error) {
	collection := db.client.Database("pcap").Collection("pcap")

	opts := options.Find().SetSort(bson.M{"time": -1}).SetLimit(int64(limit))
	cur, err := collection.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to find last flows: %v", err)
	}
	defer cur.Close(ctx)

	var results []FlowEntry
	for cur.Next(ctx) {
		var entry FlowEntry
		if err := cur.Decode(&entry); err == nil {
			results = append(results, entry)
		}
	}
	return results, nil
}

type GetFlowsOptions struct {
	FromTime    int64
	ToTime      int64
	IncludeTags []string
	ExcludeTags []string
	DstPort     int
	DstIp       string
	SrcPort     int
	SrcIp       string
	Limit       int
	Offset      int
	FlowData    string // Optional data field to filter flows by
}

func (db MongoDatabase) GetFlows(ctx context.Context, opts *GetFlowsOptions) ([]FlowEntry, error) {
	collection := db.client.Database("pcap").Collection("pcap")
	query := bson.M{}

	findOpts := options.Find().SetSort(bson.M{"time": -1})

	if opts != nil {
		if opts.Limit > 0 {
			findOpts.SetLimit(int64(opts.Limit))
		} else {
			findOpts.SetLimit(100) // Default limit if not specified
		}

		if opts.Offset > 0 {
			findOpts.SetSkip(int64(opts.Offset))
		}

		timeQuery := bson.M{}
		if opts.FromTime > 0 {
			timeQuery["$gte"] = opts.FromTime
		}
		if opts.ToTime > 0 {
			timeQuery["$lt"] = opts.ToTime
		}

		if len(timeQuery) > 0 {
			query["time"] = timeQuery
		}

		if opts.DstPort > 0 {
			query["dst_port"] = opts.DstPort
		}
		if opts.DstIp != "" {
			query["dst_ip"] = opts.DstIp
		}
		if opts.SrcPort > 0 {
			query["src_port"] = opts.SrcPort
		}
		if opts.SrcIp != "" {
			query["src_ip"] = opts.SrcIp
		}

		tagQueries := bson.M{}
		if len(opts.IncludeTags) > 0 {
			tagQueries["$all"] = opts.IncludeTags
		}
		if len(opts.ExcludeTags) > 0 {
			tagQueries["$nin"] = opts.ExcludeTags
		}
		if len(tagQueries) > 0 {
			query["tags"] = tagQueries
		}

		if opts.FlowData != "" {
			// Corretto: cerca la regex su tutti i campi 'data' dentro l'array 'flow'
			query["flow.data"] = bson.M{"$regex": opts.FlowData, "$options": "i"} // Case-insensitive regex match
		}
	}

	cur, err := collection.Find(ctx, query, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find flows: %v", err)
	}
	defer cur.Close(ctx)

	var results []FlowEntry
	for cur.Next(ctx) {
		var entry FlowEntry
		if err := cur.Decode(&entry); err == nil {
			results = append(results, entry)
		}
	}
	return results, nil
}

func (db MongoDatabase) GetFlowByID(ctx context.Context, id string) (*FlowEntry, error) {
	collection := db.client.Database("pcap").Collection("pcap")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}
	var flow FlowEntry
	if err := collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&flow); err != nil {
		return nil, err
	}
	return &flow, nil
}

// FlagIdEntry rappresenta un flagid estratto dal DB
// (replica la struct usata in assembler/flagid.go)
type FlagIdEntry struct {
	Service     string
	Team        int
	Round       int
	Description string
	FlagId      string
}

// GetRecentFlagIds estrae tutti i flagid dal DB (ultimi 5 round, con descrizione)
func (db MongoDatabase) GetFlagIds() ([]FlagIdEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	col := db.client.Database("pcap").Collection("flagids")
	filter := bson.M{}

	cur, err := col.Find(ctx, filter)
	if err != nil {
		slog.Error("[DEBUG] Errore durante Find in MongoDB", "error", err)
		return nil, err
	}
	defer cur.Close(ctx)

	entries := make([]FlagIdEntry, 0)
	for cur.Next(ctx) {
		var doc bson.M
		if err := cur.Decode(&doc); err != nil {
			slog.Error("[DEBUG] Errore nel decode del documento MongoDB", "error", err)
			continue
		}
		entry := FlagIdEntry{}
		if v, ok := doc["service"].(string); ok {
			entry.Service = v
		}
		switch v := doc["team"].(type) {
		case int32:
			entry.Team = int(v)
		case int64:
			entry.Team = int(v)
		case float64:
			entry.Team = int(v)
		case int:
			entry.Team = v
		}
		switch v := doc["round"].(type) {
		case int32:
			entry.Round = int(v)
		case int64:
			entry.Round = int(v)
		case float64:
			entry.Round = int(v)
		case int:
			entry.Round = v
		}
		if v, ok := doc["description"].(string); ok {
			entry.Description = v
		}
		if v, ok := doc["flagid"].(string); ok {
			entry.FlagId = v
		}
		if entry.FlagId != "" {
			entries = append(entries, entry)
		}
	}
	if err := cur.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (db MongoDatabase) GetClient() *mongo.Client {
	return db.client
}
