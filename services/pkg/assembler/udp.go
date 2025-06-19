// SPDX-FileCopyrightText: 2022 Qyn <qyn-ctf@gmail.com>
// SPDX-FileCopyrightText: 2023 liskaant <liskaant@gmail.com>
// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package assembler

import (
	"tulip/pkg/db"

	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// UdpAssembler is responsible for assembling UDP streams from packets.
type UdpAssembler struct {
	Streams map[UdpStreamIdendifier]*UdpStream
}

func NewUdpAssembler() *UdpAssembler {
	return &UdpAssembler{
		Streams: map[UdpStreamIdendifier]*UdpStream{},
	}
}

func (assembler *UdpAssembler) Assemble(flow gopacket.Flow, udp *layers.UDP, captureInfo *gopacket.CaptureInfo, source string) *UdpStream {
	endpointSrc := flow.Src().FastHash()
	endpointDst := flow.Dst().FastHash()
	portSrc := uint16(udp.SrcPort)
	portDst := uint16(udp.DstPort)
	id := UdpStreamIdendifier{}

	if endpointSrc > endpointDst {
		id.EndpointLower = endpointDst
		id.EndpointUpper = endpointSrc
	} else {
		id.EndpointLower = endpointSrc
		id.EndpointUpper = endpointDst
	}

	if portSrc > portDst {
		id.PortLower = portDst
		id.PortUpper = portSrc
	} else {
		id.PortLower = portSrc
		id.PortUpper = portDst
	}

	stream, ok := assembler.Streams[id]
	if !ok {
		stream = &UdpStream{
			Identifier: id,
			Flow:       flow,
			PortSrc:    udp.SrcPort,
			PortDst:    udp.DstPort,
			Source:     source,
		}

		assembler.Streams[id] = stream
	}

	stream.ProcessSegment(flow, udp, captureInfo)
	return stream
}

func (assembler *UdpAssembler) CompleteOlderThan(threshold time.Time) []*db.FlowEntry {
	flows := make([]*db.FlowEntry, 0)

	for id, stream := range assembler.Streams {
		if stream.LastSeen.Unix() < threshold.Unix() {
			flows = append(flows, assembler.CompleteReassembly(stream))
			delete(assembler.Streams, id)
		}
	}

	return flows
}

func (a *UdpAssembler) CompleteReassembly(stream *UdpStream) *db.FlowEntry {
	if len(stream.Items) == 0 {
		return nil // No items in the stream, nothing to return
	}

	firstPkt := stream.Items[0]
	lastPkt := stream.Items[len(stream.Items)-1]

	startTime := firstPkt.Time
	duration := lastPkt.Time - startTime

	src, dst := stream.Flow.Endpoints()

	return &db.FlowEntry{
		SrcPort:      int(stream.PortSrc),
		DstPort:      int(stream.PortDst),
		SrcIp:        src.String(),
		DstIp:        dst.String(),
		Time:         startTime,
		Duration:     duration,
		Num_packets:  int(stream.PacketCount),
		ParentId:     primitive.NilObjectID,
		ChildId:      primitive.NilObjectID,
		Blocked:      false,
		Tags:         []string{"udp"},
		Suricata:     []int{},
		Filename:     stream.Source,
		Flow:         stream.Items,
		Flags:        []string{},
		Flagids:      []string{},
		Fingerprints: []uint32{},
		Size:         int(stream.PacketSize),
	}
}
