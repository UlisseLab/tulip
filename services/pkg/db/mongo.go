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
	"log/slog"
	"strconv"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type mongoDb struct {
	client *mongo.Client

	flowColl      *mongo.Collection // Collection for pcap files
	signatureColl *mongo.Collection // Collection for signatures
	tagsColl      *mongo.Collection // Collection for tags
}

func NewMongoDatabase(ctx context.Context, uri string) (Database, error) {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("failed to ping MongoDB: %v", err)
	}

	db := &mongoDb{
		client:        client,
		flowColl:      client.Database("pcap").Collection("pcap"),
		signatureColl: client.Database("pcap").Collection("signatures"),
		tagsColl:      client.Database("pcap").Collection("tags"),
	}

	return db, nil
}

// GetTagList returns all tag names (_id) from the tags collection
func (db *mongoDb) GetTagList(ctx context.Context) ([]string, error) {
	cur, err := db.tagsColl.Find(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to find tags: %v", err)
	}
	defer cur.Close(ctx)

	tags := make([]string, 0)
	var tag struct {
		ID string `bson:"_id"`
	}
	for cur.Next(ctx) {
		if err := cur.Decode(&tag); err == nil {
			tags = append(tags, tag.ID)
		}
	}
	return tags, nil
}

// CountFlows returns the number of flows matching the given filters.
func (db *mongoDb) CountFlows(ctx context.Context, filters bson.D) (int64, error) {
	return db.flowColl.CountDocuments(ctx, filters)
}

// GetSignature returns a signature document by its integer ID or ObjectID string
func (db *mongoDb) GetSignaturesBatch(ctx context.Context, ids []string) ([]SuricataSig, error) {
	objIDs := make([]primitive.ObjectID, 0, len(ids))
	for _, id := range ids {
		if objID, err := primitive.ObjectIDFromHex(id); err == nil {
			objIDs = append(objIDs, objID)
		}
	}
	var results []SuricataSig
	if len(objIDs) == 0 {
		return results, nil
	}
	cursor, err := db.signatureColl.Find(ctx, bson.M{"_id": bson.M{"$in": objIDs}})
	if err != nil {
		return nil, err
	}
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}
	return results, nil
}

func (db *mongoDb) GetSignature(ctx context.Context, id string) (SuricataSig, error) {
	var result SuricataSig
	var filter bson.M

	objID, err := primitive.ObjectIDFromHex(id)
	if err == nil {
		filter = bson.M{"_id": objID}
	}

	if filter == nil {
		// If ObjectID conversion failed, try as integer ID
		idInt, err := strconv.Atoi(id)
		if err != nil {
			return result, fmt.Errorf("invalid id: %v", id)
		}
		filter = bson.M{"id": idInt}
	}

	err = db.signatureColl.FindOne(ctx, filter).Decode(&result)
	return result, err
}

// SetStar sets or unsets the "starred" tag on a flow
func (db *mongoDb) SetStar(ctx context.Context, flowId string, star bool) error {
	collection := db.client.Database("pcap").Collection("pcap")
	objID, err := primitive.ObjectIDFromHex(flowId)
	if err != nil {
		return err
	}
	var update bson.M
	if star {
		update = bson.M{"$push": bson.M{"tags": "starred"}}
	} else {
		update = bson.M{"$pull": bson.M{"tags": "starred"}}
	}
	_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	return err
}

// GetFlowDetail returns a flow by its ObjectID string
func (db *mongoDb) GetFlowDetail(ctx context.Context, id string) (*FlowEntry, error) {
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

func (db *mongoDb) ConfigureDatabase() error {
	err := db.InsertTags(context.Background(), []string{
		"flag-in",
		"flag-out",
		"blocked",
		"suricata",
		"starred",
		"flagid",
		"tcp",
		"udp",
	})
	if err != nil {
		return fmt.Errorf("error inserting initial tags: %v", err)
	}

	err = db.ConfigureIndexes()
	if err != nil {
		return fmt.Errorf("error configuring indexes: %v", err)
	}
	return nil
}

func (db *mongoDb) ConfigureIndexes() error {
	// create Index
	flowCollection := db.client.Database("pcap").Collection("pcap")

	_, err := flowCollection.Indexes().CreateMany(context.Background(), []mongo.IndexModel{
		// time index (range filtering)
		{Keys: bson.D{{Key: "time", Value: 1}}},
		// data index (context filtering)
		{Keys: bson.D{{Key: "data", Value: "text"}}},
		// port combo index (traffic correlation)
		{Keys: bson.D{{Key: "src_port", Value: 1}, {Key: "dst_port", Value: 1}}},
		// compound index for enricher lookups (AddSignatureToFlow / AddTagsToFlow 5-tuple + time window)
		{Keys: bson.D{
			{Key: "src_ip", Value: 1},
			{Key: "dst_ip", Value: 1},
			{Key: "src_port", Value: 1},
			{Key: "dst_port", Value: 1},
			{Key: "time", Value: 1},
		}},
	})

	if err != nil {
		return fmt.Errorf("error creating indexes: %v", err)
	}
	return nil
}

// Flows are either coming from a file, in which case we'll dedupe them by pcap file name.
// If they're coming from a live capture, we can do pretty much the same thing, but we'll
// just have to come up with a label. (e.g. capture-<epoch>)
// We can always swap this out with something better, but this is how flower currently handles deduping.
//
// A single flow is defined by a db.FlowEntry" struct, containing an array of flowitems and some metadata
func (db mongoDb) InsertFlows(ctx context.Context, flows []FlowEntry) error {
	flowCollection := db.client.Database("pcap").Collection("pcap")
	if len(flows) == 0 {
		return nil // No flows to insert
	}

	docs := make([]any, len(flows))
	for i, flow := range flows {
		docs[i] = flow
	}

	_, err := flowCollection.InsertMany(ctx, docs)
	if err != nil {
		return fmt.Errorf("error occurred while inserting multiple records: %v", err)
	}
	return nil
}

// Insert a new pcap uri, returns true if the pcap was not present yet,
// otherwise returns false
func (db *mongoDb) InsertPcap(ctx context.Context, pcap PcapFile) error {
	files := db.client.Database("pcap").Collection("filesImported")

	// it could already be present, so let's update it
	filter := bson.M{"file_name": pcap.FileName}

	_, err := files.ReplaceOne(ctx, filter, pcap, options.Replace().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("error occurred while inserting pcap file: %v", err)
	}
	return nil
}

func (db mongoDb) GetPcap(ctx context.Context, uri string) (bool, PcapFile) {
	files := db.client.Database("pcap").Collection("filesImported")

	cur := files.FindOne(ctx, bson.M{"file_name": uri})

	var result PcapFile
	err := cur.Decode(&result)
	if err == mongo.ErrNoDocuments {
		// No document found, return empty result
		return false, PcapFile{}
	} else if err != nil {
		return true, PcapFile{}
	}

	return true, result
}

// AddSignature adds a signature to the database, returning its MongoDB ID and error.
func (db mongoDb) AddSignature(ctx context.Context, sig SuricataSig) (primitive.ObjectID, error) {
	sigCollection := db.client.Database("pcap").Collection("signatures")

	// Build the query to check for an existing signature
	query := bson.M{
		"id":     sig.ID,
		"msg":    sig.Msg,
		"action": sig.Action,
		"tag":    sig.Tag,
	}

	var existingSig SuricataSig
	err := sigCollection.FindOne(ctx, query).Decode(&existingSig)
	if err == nil {
		// Signature exists, return its MongoDB ID
		return existingSig.MongoID, nil
	}
	if err != mongo.ErrNoDocuments {
		// Some other error occurred
		return primitive.ObjectID{}, fmt.Errorf("failed to check for existing signature: %v", err)
	}

	// Signature does not exist, insert it
	res, err := sigCollection.InsertOne(ctx, sig)
	if err != nil {
		return primitive.ObjectID{}, fmt.Errorf("failed to insert signature: %v", err)
	}

	insertedID, ok := res.InsertedID.(primitive.ObjectID)
	if !ok {
		return primitive.ObjectID{}, fmt.Errorf("inserted ID is not an ObjectID")
	}
	return insertedID, nil
}

// flowIdFilter returns a filter for finding flows that match the given FlowID
// and have a time within the specified window (in milliseconds).
func flowIdFilter(flow FlowID, window int) bson.M {
	epoch := int(flow.Time.UnixNano() / 1000000)
	filter := bson.M{
		"src_port": flow.SrcPort,
		"dst_port": flow.DstPort,
		"src_ip":   flow.SrcIp,
		"dst_ip":   flow.DstIp,
		"time": bson.M{
			"$gt": epoch - window,
			"$lt": epoch + window,
		},
	}
	return filter
}

// AddSignatureToFlow adds a signature to a flow, updating the flow's tags and blocked status if necessary.
func (db *mongoDb) AddSignatureToFlow(ctx context.Context, flow FlowID, sig SuricataSig, window int) error {
	// Add the signature to the collection
	sigObjectId, err := db.AddSignature(ctx, sig)
	if err != nil {
		return fmt.Errorf("failed to add signature: %v", err)
	}

	filter := flowIdFilter(flow, window)

	tags := []string{"suricata"}
	// Add tag from the signature if it contained one
	if sig.Tag != "" {
		err := db.InsertTag(ctx, sig.Tag)
		if err != nil {
			return fmt.Errorf("failed to insert tag: %v", err)
		}
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
				"suricata": sigObjectId,
			},
		}
	} else {
		update = bson.M{
			"$addToSet": bson.M{
				"tags": bson.M{
					"$each": tags,
				},
				"suricata": sigObjectId,
			},
		}
	}

	flowCollection := db.client.Database("pcap").Collection("pcap")
	res, err := flowCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update flow: %v", err)
	} else if res.MatchedCount == 0 {
		return fmt.Errorf("no flow matched the given filter")
	}

	// If we updated the flow, we can return nil error
	return nil
}

// AddTagsToFlow adds tags to a flow, without duplicating existing tags.
func (db *mongoDb) AddTagsToFlow(ctx context.Context, flow FlowID, tags []string, window int) error {
	filter := flowIdFilter(flow, window)

	// Update this flow with the tags
	update := bson.M{
		"$addToSet": bson.M{"tags": bson.M{"$each": tags}},
	}

	// Apply update to database
	flowCollection := db.client.Database("pcap").Collection("pcap")
	res, err := flowCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update flow: %v", err)
	} else if res.MatchedCount == 0 {
		return fmt.Errorf("no flow matched the given filter")
	}

	return nil
}

func (db *mongoDb) InsertTags(ctx context.Context, tags []string) error {
	tagCollection := db.client.Database("pcap").Collection("tags")

	docs := make([]any, len(tags))
	for i, tag := range tags {
		docs[i] = bson.M{"_id": tag}
	}

	// Insert all tags at once, ignoring duplicates (and ignoring error too, since we don't care about existing tags)
	// SetOrdered(false) allows MongoDB to continue inserting other documents even if one fails
	// TODO: handle this better?
	_, _ = tagCollection.InsertMany(ctx, docs, options.InsertMany().SetOrdered(false))
	return nil
}

func (db *mongoDb) InsertTag(ctx context.Context, tag string) error {
	tagCollection := db.client.Database("pcap").Collection("tags")
	// we ignore the error here, since we don't care if the tag already exists
	// TODO: handle this better?
	_, _ = tagCollection.InsertOne(ctx, bson.M{"_id": tag})
	return nil
}

func (db mongoDb) GetLastFlows(ctx context.Context, limit int) ([]FlowEntry, error) {
	return db.GetFlows(ctx, &FindFlowsOptions{Limit: limit})
}

func (db mongoDb) GetFlows(ctx context.Context, opts *FindFlowsOptions) ([]FlowEntry, error) {
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

		if len(opts.Fingerprints) > 0 {
			// search for fingerprints in the flow.fingerprints array
			query["fingerprints"] = bson.M{"$in": opts.Fingerprints}
		}
	}

	cur, err := collection.Find(ctx, query, findOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to find flows: %v", err)
	}
	defer func() {

	}()

	var results []FlowEntry
	err = cur.All(ctx, &results)
	if err != nil {
		return nil, fmt.Errorf("failed to decode flows: %v", err)
	}

	return results, nil
}

func (db mongoDb) GetFingerprints(ctx context.Context) ([]int, error) {
	collection := db.client.Database("pcap").Collection("pcap")

	cur, err := collection.Distinct(ctx, "fingerprints", bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to get distinct fingerprints: %v", err)
	}

	fingerprints := make([]int, 0, len(cur))
	for _, v := range cur {
		if fingerprint, ok := v.(int64); ok {
			fingerprints = append(fingerprints, int(fingerprint))
		} else {
			slog.Warn("Non-integer fingerprint found", "value", v)
		}
	}

	return fingerprints, nil
}
