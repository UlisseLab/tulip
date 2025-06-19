// SPDX-FileCopyrightText: 2022 Qyn <qyn-ctf@gmail.com>
// SPDX-FileCopyrightText: 2023 liskaant <liskaant@gmail.com>
// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package assembler

import (
	"time"
	"tulip/pkg/db"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type UdpStreamIdendifier struct {
	EndpointLower uint64
	EndpointUpper uint64
	PortLower     uint16
	PortUpper     uint16
}

type UdpStream struct {
	Identifier  UdpStreamIdendifier
	Flow        gopacket.Flow
	PacketCount uint
	PacketSize  uint
	Items       []db.FlowItem
	PortSrc     layers.UDPPort
	PortDst     layers.UDPPort
	Source      string
	LastSeen    time.Time
}

func (stream *UdpStream) ProcessSegment(flow gopacket.Flow, udp *layers.UDP, captureInfo *gopacket.CaptureInfo) {
	if len(udp.Payload) == 0 {
		return
	}

	from := "s"
	if flow.Dst().FastHash() == stream.Flow.Src().FastHash() {
		from = "c"
	}

	stream.LastSeen = captureInfo.Timestamp
	stream.PacketCount += 1
	stream.PacketSize += uint(len(udp.Payload))

	// We have to make sure to stay under the document limit
	available := uint(streamdoc_limit) - stream.PacketSize

	length := uint(len(udp.Payload))

	// clamp length to [0, available]
	length = min(length, available)
	length = max(length, 0)

	stream.Items = append(stream.Items, db.FlowItem{
		From: from,
		Data: string(udp.Payload[:length]),
		Time: int(captureInfo.Timestamp.UnixNano() / 1000000), // TODO; maybe use int64?
	})
}
