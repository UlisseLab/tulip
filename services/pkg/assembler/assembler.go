// SPDX-FileCopyrightText: 2022 Rick de Jager <rickdejager99@gmail.com>
// SPDX-FileCopyrightText: 2022 erdnaxe <erdnaxe@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 - 2024 gfelber <34159565+gfelber@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 - 2025 Eyad Issa <eyadlorenzo@gmail.com>
// SPDX-FileCopyrightText: 2023 Max Groot <19346100+MaxGroot@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 Sijisu <mail@sijisu.eu>
// SPDX-FileCopyrightText: 2023 liskaant <50048810+liskaant@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 liskaant <liskaant@gmail.com>
// SPDX-FileCopyrightText: 2023 meme-lord <meme-lord@users.noreply.github.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package assembler

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"time"
	"tulip/pkg/db"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/reassembly"
	"github.com/panjf2000/ants/v2"
)

type Service struct {
	Config

	Defragmenter  *ip4defrag.IPv4Defragmenter
	StreamFactory *TcpStreamFactory
	StreamPool    *reassembly.StreamPool

	AssemblerTcp *reassembly.Assembler
	AssemblerUdp *UdpAssembler

	flowChannel chan db.FlowEntry // Channel for processed flow entries
}

type Config struct {
	DB            db.Database    // the database to use for storing flows
	FlushInterval time.Duration  // Interval to flush non-terminated connections
	FlagRegex     *regexp.Regexp // Regex to apply for flagging flows
	TcpLazy       bool           // Lazy decoding for TCP packets
	Experimental  bool           // Experimental features enabled
	NonStrict     bool           // Non-strict mode for TCP stream assembly

	ConnectionTcpTimeout time.Duration
	ConnectionUdpTimeout time.Duration

	FlagIdUrl string // URL del servizio flagid
}

func NewAssemblerService(opts Config) *Service {
	streamFactory := &TcpStreamFactory{
		nonStrict: opts.NonStrict,
	}

	streamPool := reassembly.NewStreamPool(streamFactory)
	assemblerUdp := NewUdpAssembler()

	srv := &Service{
		Defragmenter:  ip4defrag.NewIPv4Defragmenter(),
		StreamFactory: streamFactory,
		StreamPool:    streamPool,

		AssemblerTcp: reassembly.NewAssembler(streamPool),
		AssemblerUdp: assemblerUdp,

		flowChannel: make(chan db.FlowEntry), // Buffered channel for flow entries
	}
	srv.Config = opts

	onComplete := func(fe db.FlowEntry) { srv.reassemblyCallback(fe) }
	srv.StreamFactory.OnComplete = onComplete

	go srv.insertFlows()

	return srv
}

// HandlePcapUri processes a PCAP file from a given URI.
func (s *Service) HandlePcapUri(ctx context.Context, fname string) {
	file, err := os.Open(fname)
	if err != nil {
		slog.Error("Failed to open PCAP file", "file", fname, "err", err)
		return
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		slog.Error("Failed to create PCAP reader", "file", fname, "err", err)
		return
	}

	s.ProcessPcapHandle(ctx, reader, fname)
}

// FlushConnections closes and saves connections that are older than the configured timeouts.
func (s *Service) FlushConnections() {
	thresholdTcp := time.Now().Add(-s.ConnectionTcpTimeout)
	thresholdUdp := time.Now().Add(-s.ConnectionUdpTimeout)
	flushed, closed, discarded := 0, 0, 0

	if s.ConnectionTcpTimeout != 0 {
		flushed, closed = s.AssemblerTcp.FlushCloseOlderThan(thresholdTcp)
		discarded = s.Defragmenter.DiscardOlderThan(thresholdTcp)
	}

	if flushed != 0 || closed != 0 || discarded != 0 {
		slog.Info("Flushed connections", "flushed", flushed, "closed", closed, "discarded", discarded)
	}

	if s.ConnectionUdpTimeout != 0 {
		udpFlows := s.AssemblerUdp.CompleteOlderThan(thresholdUdp)
		for _, flow := range udpFlows {
			s.reassemblyCallback(*flow)
		}

		if len(udpFlows) != 0 {
			slog.Info("Assembled UDP flows", "count", len(udpFlows))
		}
	}
}

// ProcessPcapHandle processes a PCAP handle, reading packets and processing them.
func (s *Service) ProcessPcapHandle(ctx context.Context, handle *pcapgo.Reader, fname string) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Recovered from panic in ProcessPcapHandle", "error", r, "file", fname)
		}
	}()

	// Check if the file has already been processed
	exists, file := s.DB.GetPcap(fname)
	processedCount := int64(0)
	if exists {
		if file.Finished {
			slog.Info("PCAP file already processed", "file", fname)
			return
		}
		processedCount = file.Position
		slog.Info("skipping already processed packets", "file", fname, "count", processedCount)
	}

	source := s.setupPacketSource(handle)
	s.FlushConnections()

	count, lastFlush := int64(0), time.Now()
	bytes := int64(0)
	nodefrag := false

	startTime := time.Now()

	finished := true

packetLoop:
	for packet := range source.Packets() {
		select {
		case <-ctx.Done():
			slog.Warn("context cancelled, stopping packet processing", "file", fname)
			finished = false
			break packetLoop
		default:
		}

		count++
		if count < processedCount+1 {
			continue // skip already processed packets
		}

		data := packet.Data()
		bytes += int64(len(data))
		done := s.processPacket(packet, fname, nodefrag)
		if done {
			finished = false
			break
		}

		if s.shouldFlushConnections(lastFlush) {
			s.FlushConnections()
			lastFlush = time.Now()
		}
	}

	elapsed := time.Since(startTime)
	avgPkts := float64(count) / elapsed.Seconds()
	avgMBytes := float64(bytes) / elapsed.Seconds() / 1e6 // MB/s
	slog.Info("Processed packets",
		"count", count-processedCount,
		"elapsed", elapsed,
		"pkt/s", fmt.Sprintf("%.2f", avgPkts),
		"MB/s", fmt.Sprintf("%.2f", avgMBytes),
		"file", fname, "finished", finished,
	)

	s.DB.InsertPcap(db.PcapFile{
		FileName: fname,
		Position: count,
		Finished: finished,
	})
}

// checkProcessedCount returns the count of already processed packets for a given file.
func (s *Service) checkProcessedCount(fname string) int64 {
	exists, file := s.DB.GetPcap(fname)
	if exists {
		return file.Position
	}
	return 0
}

// setupPacketSource initializes the gopacket.PacketSource based on the link type.
func (s *Service) setupPacketSource(handle *pcapgo.Reader) *gopacket.PacketSource {
	linktype := handle.LinkType()
	var source *gopacket.PacketSource
	switch linktype {
	case layers.LinkTypeIPv4:
		source = gopacket.NewPacketSource(handle, layers.LayerTypeIPv4)
	default:
		source = gopacket.NewPacketSource(handle, linktype)
	}
	source.Lazy = s.TcpLazy
	source.NoCopy = true
	return source
}

// processPacket handles a single packet: skipping, defragmentation, protocol dispatch (TCP/UDP), and error handling.
// Returns true if processing should stop.
func (s *Service) processPacket(packet gopacket.Packet, fname string, nodefrag bool) bool {
	// defrag the IPv4 packet if required
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if !nodefrag && ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		l := ip4.Length
		newip4, err := s.Defragmenter.DefragIPv4(ip4)
		if err != nil {
			slog.Error("Error while de-fragmenting", "err", err)
			return true
		} else if newip4 == nil {
			return false // packet fragment, we don't have whole packet yet.
		}
		if newip4.Length != l {
			pb, ok := packet.(gopacket.PacketBuilder)
			if !ok {
				panic("Not a PacketBuilder")
			}
			nextDecoder := newip4.NextLayerType()
			nextDecoder.Decode(newip4.Payload, pb)
		}
	}

	transport := packet.TransportLayer()
	if transport == nil {
		return false
	}

	switch transport.LayerType() {
	case layers.LayerTypeTCP:
		tcp := transport.(*layers.TCP)
		flow := packet.NetworkLayer().NetworkFlow()
		captureInfo := packet.Metadata().CaptureInfo
		captureInfo.AncillaryData = []any{fname}
		context := &Context{CaptureInfo: captureInfo}
		s.AssemblerTcp.AssembleWithContext(flow, tcp, context)
	case layers.LayerTypeUDP:
		udp := transport.(*layers.UDP)
		flow := packet.NetworkLayer().NetworkFlow()
		captureInfo := packet.Metadata().CaptureInfo
		s.AssemblerUdp.Assemble(flow, udp, &captureInfo, fname)
	default:
		slog.Warn("Unsupported transport layer", "layer", transport.LayerType().String(), "file", fname)
	}
	return false
}

// shouldFlushConnections determines if it's time to flush connections based on the interval.
func (s *Service) shouldFlushConnections(lastFlush time.Time) bool {
	return s.FlushInterval != 0 && lastFlush.Add(s.FlushInterval).Unix() < time.Now().Unix()
}

// TODO; FIXME; RDJ; this is kinda gross, but this is PoC level code
func (s *Service) reassemblyCallback(entry db.FlowEntry) {
	s.parseAndTagHttp(&entry)
	s.applyFlagRegexTags(&entry)
	s.insertFlowEntry(&entry)
}

// parseAndTagHttp parses HTTP flows and decodes encodings to plaintext.
func (s *Service) parseAndTagHttp(entry *db.FlowEntry) {
	s.ParseHttpFlow(entry)
}

// applyFlagRegexTags applies regex-based tags to the flow entry.
func (s *Service) applyFlagRegexTags(entry *db.FlowEntry) {
	if s.FlagRegex == nil {
		return
	}
	ApplyFlagTags(entry, *s.FlagRegex)
}

// insertFlowEntry inserts the processed flow entry into the database.
func (s *Service) insertFlowEntry(entry *db.FlowEntry) {
	s.flowChannel <- *entry // Send to channel for processing
}

func (s *Service) insertFlows() error {
	const maxWorkers = 100

	pool, err := ants.NewPool(maxWorkers, ants.WithPreAlloc(true))
	if err != nil {
		return fmt.Errorf("failed to create goroutine pool: %w", err)
	}

	for entry := range s.flowChannel {
		pool.Submit(func() {
			s.DB.InsertFlow(entry)
		})
	}

	pool.Release()
	return nil
}
