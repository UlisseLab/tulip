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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

type Database interface {
	GetFlowList(filters bson.M) ([]FlowEntry, error) // Get a list of flows with optional filters
	GetTagList() ([]string, error)                   // Get a list of all tags
	GetSignature(id string) (Signature, error)       // Get a signature by ID
	SetStar(flowID string, star bool) error          // Set or unset the "starred" tag on a flow
	GetFlowDetail(id string) (*FlowEntry, error)     // Get detailed flow information by ID
	InsertFlow(flow FlowEntry)                       // Insert a new flow into the database
	GetPcap(uri string) (bool, PcapFile)             // Check if a pcap file exists and return its metadata
	InsertPcap(uri string, position int64) bool      // Insert a new pcap file or update its position
}
