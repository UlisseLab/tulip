package assembler

import (
	"sync"
	"tulip/pkg/db"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// TcpStream implements reassembly.Stream for TCP streams.
type TcpStream struct {
	tcpFSM    *reassembly.TCPSimpleFSM
	tcpFSMErr bool

	optChecker reassembly.TCPOptionCheck
	net        gopacket.Flow
	transport  gopacket.Flow

	// RDJ; These field are added to make mongo convertion easier
	source     string
	FlowItems  []db.FlowItem
	srcPort    layers.TCPPort
	dstPort    layers.TCPPort
	totalSize  int
	numPackets int

	nonStrict bool // non-strict mode, used for testing

	mu sync.Mutex

	onComplete func(db.FlowEntry) // Callback to call when the stream is complete
}

func (t *TcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM
	if !t.tcpFSM.CheckState(tcp, dir) {
		if !t.tcpFSMErr {
			t.tcpFSMErr = true
		}

		if !t.nonStrict {
			return false
		}
	}

	// We just ignore the Checksum
	return true
}

// ReassembledSG is called zero or more times.
// ScatterGather is reused after each Reassembled call,
// so it's important to copy anything you need out of it,
// especially bytes (or use KeepFrom())
func (t *TcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, _ := sg.Info()
	length, _ := sg.Lengths()
	capInfo := ac.GetCaptureInfo()
	timestamp := capInfo.Timestamp
	t.numPackets += 1

	// Don't add empty streams to the DB
	if length == 0 {
		return
	}

	data := sg.Fetch(length)

	// We have to make sure to stay under the document limit
	t.totalSize += length
	bytes_available := streamdoc_limit - t.totalSize
	if length > bytes_available {
		length = bytes_available
	}
	if length < 0 {
		length = 0
	}
	string_data := string(data[:length])

	var from string
	if dir == reassembly.TCPDirClientToServer {
		from = "c"
	} else {
		from = "s"
	}

	// consolidate subsequent elements from the same origin
	l := len(t.FlowItems)
	if l > 0 {
		if t.FlowItems[l-1].From == from {
			t.FlowItems[l-1].Data += string_data
			// All done, no need to add a new item
			return
		}
	}

	// Add a FlowItem based on the data we just reassembled
	t.FlowItems = append(t.FlowItems, db.FlowItem{
		Data: string_data,
		From: from,
		Time: int(timestamp.UnixNano() / 1000000), // TODO; maybe use int64?
	})

}

// ReassemblyComplete is called when assembly decides there is
// no more data for this Stream, either because a FIN or RST packet
// was seen, or because the stream has timed out without any new
// packet data (due to a call to FlushCloseOlderThan).
// It should return true if the connection should be removed from the pool
// It can return false if it want to see subsequent packets with Accept(), e.g. to
// see FIN-ACK, for deeper state-machine analysis.
func (t *TcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {

	// Insert the stream into the mogodb.

	/*
		{
			"src_port": 32858,
			"dst_ip": "10.10.3.1",
			"contains_flag": false,
			"flow": [{}],
			"filename": "services/test_pcap/dump-2018-06-27_13:25:31.pcap",
			"src_ip": "10.10.3.126",
			"dst_port": 8080,
			"time": 1530098789655,
			"duration": 96,
			"inx": 0,
		}
	*/
	src, dst := t.net.Endpoints()
	var time, duration int
	if len(t.FlowItems) == 0 {
		// No point in inserting this element, it has no data and even if we wanted to,
		// we can't timestamp it so the front-end can't display it either
		return false
	}

	time = t.FlowItems[0].Time
	duration = t.FlowItems[len(t.FlowItems)-1].Time - time

	entry := db.FlowEntry{
		SrcPort:     int(t.srcPort),
		DstPort:     int(t.dstPort),
		SrcIp:       src.String(),
		DstIp:       dst.String(),
		Time:        time,
		Duration:    duration,
		Num_packets: t.numPackets,
		ParentId:    primitive.NilObjectID,
		ChildId:     primitive.NilObjectID,
		Blocked:     false,
		Tags:        []string{"tcp"},
		Suricata:    make([]int, 0),
		Filename:    t.source,
		Flow:        t.FlowItems,
		Size:        t.totalSize,
		Flags:       make([]string, 0),
		Flagids:     make([]string, 0),
	}

	t.onComplete(entry)

	// do not remove the connection to allow last ACK
	return false
}
