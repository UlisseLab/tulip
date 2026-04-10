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
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type FlowItemFrom string

const (
	FlowItemFromServer FlowItemFrom = "s" // Flow item from server
	FlowItemFromClient FlowItemFrom = "c" // Flow item from client
)

// Added a flow struct
type FlowItem struct {
	// From can be FlowItemFromClient or FlowItemFromServer
	From FlowItemFrom `bson:"from" json:"from"`
	// Data, in a somewhat readable format
	Data string `bson:"data" json:"data"`
	// The raw data, in bytes. The `b64` tag is used because this is base64 encoded in the frontend
	Raw []byte `bson:"raw" json:"b64"`
	// Timestamp of the first packet in the flow (Epoch / ms)
	Time int `bson:"time" json:"time"`
}

type FlowEntry struct {
	Id           primitive.ObjectID `bson:"_id,omitempty" json:"_id"`       // MongoDB unique identifier
	SrcPort      int                `bson:"src_port" json:"src_port"`       // Source port
	DstPort      int                `bson:"dst_port" json:"dst_port"`       // Destination port
	SrcIp        string             `bson:"src_ip" json:"src_ip"`           // Source IP address
	DstIp        string             `bson:"dst_ip" json:"dst_ip"`           // Destination IP address
	Time         int                `bson:"time" json:"time"`               // Timestamp (epoch)
	Duration     int                `bson:"duration" json:"duration"`       // Duration in milliseconds
	NumPackets   int                `bson:"num_packets" json:"num_packets"` // Number of packets
	Blocked      bool               `bson:"blocked" json:"blocked"`
	Filename     string             `bson:"filename" json:"filename"` // Name of the pcap file this flow was captured in
	Fingerprints []uint32           `bson:"fingerprints" json:"fingerprints"`
	Suricata     []string           `bson:"suricata" json:"suricata"`
	Flow         []FlowItem         `bson:"flow" json:"flow"`
	Tags         []string           `bson:"tags" json:"tags"`       // Tags associated with this flow, e.g. "starred", "tcp", "udp", "blocked"
	Size         int                `bson:"size" json:"size"`       // Size of the flow in bytes
	Flags        []string           `bson:"flags" json:"flags"`     // Flags contained in the flow
	Flagids      []string           `bson:"flagids" json:"flagids"` // Flag IDs associated with this flow
}

type PcapFile struct {
	FileName string `bson:"file_name"` // Name of the pcap file
	Position int64  `bson:"position"`  // N. of packets processed so far
	Finished bool   `bson:"finished"`  // Indicates if the pcap file has been fully processed
}

type FindFlowsOptions struct {
	FromTime     int64
	ToTime       int64
	IncludeTags  []string
	ExcludeTags  []string
	DstPort      int
	DstIp        string
	SrcPort      int
	SrcIp        string
	Limit        int
	Offset       int
	FlowData     string // Optional data field to filter flows by
	Fingerprints []int  // Optional fingerprints to filter flows by
}

type FlowID struct {
	SrcPort int
	DstPort int
	SrcIp   string
	DstIp   string
	Time    time.Time
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

// SuricataSig represents a Suricata signature document in the database.
type SuricataSig struct {
	MongoID primitive.ObjectID `bson:"_id,omitempty"` // MongoDB ID, will be set on insert
	ID      int                `bson:"id"`            // Signature ID as created by Suricata
	Msg     string             `bson:"msg"`           // Signature message
	Action  string             `bson:"action"`        // Action to take (e.g. "alert", "block")
	Tag     string             `bson:"omitempty"`     // Optional tag for the signature
}

type Database interface {
	// Insert multiple flows into the database
	InsertFlows(ctx context.Context, flows []FlowEntry) error
	// Count the number of flows matching the given filters
	CountFlows(filters bson.D) (int64, error)
	// Set or unset the "starred" tag on a flow
	SetStar(id string, star bool) error
	// Get detailed flow information by ID
	GetFlowDetail(id string) (*FlowEntry, error)
	// Get a list of all tags
	GetTagList() ([]string, error)
	// Retrieve a Suricata signature by its ID, which can be an integer or ObjectID string.
	GetSignature(id string) (SuricataSig, error)
	// Retrieve multiple Suricata signatures by their ObjectID strings in a single query.
	GetSignaturesBatch(ctx context.Context, ids []string) ([]SuricataSig, error)
	// Retrieve a PCAP by its URI, returning whether it exists
	GetPcap(uri string) (bool, PcapFile)
	// Insert a new pcap file metadata into the database, updating if it already exists.
	InsertPcap(file PcapFile) error
	// Set up the database with initial tags and indexes
	ConfigureDatabase() error
	// Associates a Suricata signature with a flow
	AddSignatureToFlow(flow FlowID, sig SuricataSig, window int) error
	//
	InsertTags(tags []string) error
	//
	AddTagsToFlow(flow FlowID, tags []string, window int) error

	// New functions with context support

	GetFlows(ctx context.Context, opts *FindFlowsOptions) ([]FlowEntry, error)
	GetFingerprints(ctx context.Context) ([]int, error)
}
