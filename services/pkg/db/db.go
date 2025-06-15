package db

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// Added a flow struct
type FlowItem struct {
	From string `bson:"from" json:"from"` // From: "s" / "c" for server or client
	Data string `bson:"data" json:"data"` // Data, in a somewhat readable format
	B64  string `bson:"b64" json:"b64"`   // The raw data, base64 encoded. TODO: Replace this with gridfs
	Time int    `bson:"time" json:"time"` // Timestamp of the first packet in the flow (Epoch / ms)
}

type FlowEntry struct {
	Id           primitive.ObjectID `bson:"_id,omitempty" json:"_id"`       // MongoDB unique identifier
	SrcPort      int                `bson:"src_port" json:"src_port"`       // Source port
	DstPort      int                `bson:"dst_port" json:"dst_port"`       // Destination port
	SrcIp        string             `bson:"src_ip" json:"src_ip"`           // Source IP address
	DstIp        string             `bson:"dst_ip" json:"dst_ip"`           // Destination IP address
	Time         int                `bson:"time" json:"time"`               // Timestamp (epoch)
	Duration     int                `bson:"duration" json:"duration"`       // Duration in milliseconds
	Num_packets  int                `bson:"num_packets" json:"num_packets"` // Number of packets
	Blocked      bool               `bson:"blocked" json:"blocked"`
	Filename     string             `bson:"filename" json:"filename"`   // Name of the pcap file this flow was captured in
	ParentId     primitive.ObjectID `bson:"parent_id" json:"parent_id"` // Parent flow ID if this is a child flow
	ChildId      primitive.ObjectID `bson:"child_id" json:"child_id"`   // Child flow ID if this is a parent flow
	Fingerprints []uint32           `bson:"fingerprints" json:"fingerprints"`
	Suricata     []int              `bson:"suricata" json:"suricata"`
	Flow         []FlowItem         `bson:"flow" json:"flow"`
	Tags         []string           `bson:"tags" json:"tags"`       // Tags associated with this flow, e.g. "starred", "tcp", "udp", "blocked"
	Size         int                `bson:"size" json:"size"`       // Size of the flow in bytes
	Flags        []string           `bson:"flags" json:"flags"`     // Flags contained in the flow
	Flagids      []string           `bson:"flagids" json:"flagids"` // Flag IDs associated with this flow
}

type Database struct {
	client *mongo.Client
}

// GetFlowList implements filtering logic similar to the Python getFlowList
func (db Database) GetFlowList(filters bson.M) ([]FlowEntry, error) {
	collection := db.client.Database("pcap").Collection("pcap")

	opt := options.Find().
		SetSort(bson.M{"time": -1}).      // Sort by time descending
		SetProjection(bson.M{"flow": 0}). // Exclude flow details for performance
		SetLimit(100)                     // Limit to 100 results

	// If filters are nil, use an empty filter
	if filters == nil {
		filters = bson.M{}
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
		if err := cur.Decode(&entry); err == nil {
			results = append(results, entry)
		}
	}

	return results, nil
}

// GetTagList returns all tag names (_id) from the tags collection
func (db Database) GetTagList() ([]string, error) {
	collection := db.client.Database("pcap").Collection("tags")

	cur, err := collection.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to find tags: %v", err)
	}

	defer cur.Close(context.TODO())

	var tags []string
	for cur.Next(context.TODO()) {
		var tag struct {
			ID string `bson:"_id"`
		}
		if err := cur.Decode(&tag); err == nil {
			tags = append(tags, tag.ID)
		}
	}
	return tags, nil
}

// GetSignature returns a signature document by its integer ID or ObjectID string
func (db Database) GetSignature(id string) (Signature, error) {
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
func (db Database) SetStar(flowID string, star bool) error {
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
func (db Database) GetFlowDetail(id string) (*FlowEntry, error) {
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

func ConnectMongo(uri string) Database {
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(uri))
	if err != nil {
		panic(err)
	}
	if err := client.Ping(context.TODO(), readpref.Primary()); err != nil {
		panic(err)
	}

	return Database{
		client: client,
	}
}

func (db Database) ConfigureDatabase() {
	db.InsertTag("flag-in")
	db.InsertTag("flag-out")
	db.InsertTag("blocked")
	db.InsertTag("suricata")
	db.InsertTag("starred")
	db.InsertTag("flagid-in")
	db.InsertTag("flagid-out")
	db.InsertTag("tcp")
	db.InsertTag("udp")
	db.ConfigureIndexes()
}

func (db Database) ConfigureIndexes() {
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
func (db Database) InsertFlow(flow FlowEntry) {
	flowCollection := db.client.Database("pcap").Collection("pcap")

	// Process the data, so it works well in mongodb
	for idx := range flow.Flow {
		flowItem := &flow.Flow[idx]

		// Base64 encode the raw data string
		flowItem.B64 = base64.StdEncoding.EncodeToString([]byte(flowItem.Data))
		// filter the data string down to only printable characters
		flowItem.Data = strings.Map(func(r rune) rune {
			if r < 128 {
				return r
			}
			return -1
		}, flowItem.Data)
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
	FileName string `bson:"file_name"`
	Position int64  `bson:"position"`
}

// Insert a new pcap uri, returns true if the pcap was not present yet,
// otherwise returns false
func (db Database) InsertPcap(uri string, position int64) bool {
	files := db.client.Database("pcap").Collection("filesImported")
	exists, _ := db.GetPcap(uri)
	if !exists {
		files.InsertOne(context.TODO(), bson.M{"file_name": uri, "position": position})
	} else {
		files.UpdateOne(context.TODO(), bson.M{"file_name": uri}, bson.M{"$set": bson.M{"position": position}})
	}
	return !exists
}

func (db Database) GetPcap(uri string) (bool, PcapFile) {
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

func (db Database) AddSignature(sig Signature) string {
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

func (db Database) findFlowInDB(flow FlowID, window int) (mongo.Collection, bson.M) {
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

func (db Database) updateFlowInDB(flowCollection mongo.Collection, filter bson.M, update bson.M) bool {
	// Enrich the flow with tag information
	res, err := flowCollection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		log.Println("Error occured while editing record:", err)
		return false
	}

	return res.MatchedCount > 0
}

func (db Database) AddSignatureToFlow(flow FlowID, sig Signature, window int) bool {
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

func (db Database) AddTagsToFlow(flow FlowID, tags []string, window int) bool {
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
func (db Database) InsertTag(tag string) {
	tagCollection := db.client.Database("pcap").Collection("tags")
	// Yeah this will err... A lot.... Two more dev days till Athens, this will do.
	tagCollection.InsertOne(context.TODO(), bson.M{"_id": tag})
}

type Flagid struct {
	ID   primitive.ObjectID `bson:"_id"`
	Time int                `bson:"time"`
}

func (db Database) GetFlagids(flaglifetime int) ([]Flagid, error) {
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

func (db Database) GetLastFlows(ctx context.Context, limit int) ([]FlowEntry, error) {
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
}

func (db Database) GetFlows(ctx context.Context, opts *GetFlowsOptions) ([]FlowEntry, error) {
	collection := db.client.Database("pcap").Collection("pcap")
	query := bson.M{}

	findOpts := options.Find().
		SetSort(bson.M{"time": -1})

	if opts != nil {
		if opts.Limit > 0 {
			findOpts.SetLimit(int64(opts.Limit))
		} else {
			findOpts.SetLimit(100) // Default limit if not specified
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

func (db Database) GetFlowByID(ctx context.Context, id string) (*FlowEntry, error) {
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
