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
	"sync"
	"time"
	"tulip/pkg/db"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/ip4defrag"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

type TcpAssembler = reassembly.Assembler

// Service represents an assembler service, capable of reassembling level 4 traffic flows.
//
// There are mainly 3 stages:
// 1. Layer 3 (IP) defragmentation
// 2. Layer 4 (TCP/UDP) reassembly
// 3. Push back via the assembled channel
//
// The assembled channel is syncronous, which means that the process won't start unless you
// start consuming flows coming from Assembled()
type Service struct {
	Config

	// Stage 1: IP defragmentation
	defragmenter *ip4defrag.IPv4Defragmenter

	// Stage 2: TCP/UDP reassembly
	workerQueues  []chan QueueItem // One queue per worker
	numWorkers    int              // Number of TCP/UDP assembler workers
	tcpAssemblers []*TcpAssembler  // Partitioned TCP assemblers
	udpAssemblers []*UdpAssembler  // Partitioned UDP assemblers

	// we need this because when we flush we must be sure
	// that nobody is doing anything
	assemblersMu sync.RWMutex

	// Stage 3: returning assembledQueue flows
	assembledQueue chan db.FlowEntry // Channel for processed flow entries

	// Internal state
	mu        sync.Mutex   // Mutex to protect stats updates
	stats     Stats        // Statistics about processed packets, bytes, and flows
	flushTick *time.Ticker // Ticker for flushing connections
}

type Stats struct {
	Processed      int64 // Total number of processed packets
	ProcessedBytes int64 // Total number of processed bytes
	Flows          int64 // Total number of flows processed
}

type Config struct {
	DB            db.Database   // the database to use for storing flows
	FlushInterval time.Duration // Interval to flush non-terminated connections
	TcpLazy       bool          // Lazy decoding for TCP packets
	Experimental  bool          // Experimental features enabled
	NonStrict     bool          // Non-strict mode for TCP stream assembly

	Workers int // Number of workers for TCP/UDP assembly

	ConnectionTcpTimeout time.Duration
	ConnectionUdpTimeout time.Duration

	FlagIdUrl      string // URL del servizio flagid
	StreamdocLimit int    // Limit for streamdoc size, used in analysis
}

func NewAssemblerService(ctx context.Context, opts Config) *Service {

	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 5 * time.Second // Default flush interval if not set
	}

	srv := &Service{
		Config: opts,

		defragmenter:   ip4defrag.NewIPv4Defragmenter(),
		assembledQueue: make(chan db.FlowEntry),
		flushTick:      time.NewTicker(opts.FlushInterval),
	}

	var (
		tcpStreamFactory = &TcpStreamFactory{
			NonStrict:      opts.NonStrict,
			StreamdocLimit: opts.StreamdocLimit,
			OnComplete:     srv.reassemblyCallback,
		}
	)

	workers := max(1, opts.Workers) // Ensure at least one worker

	srv.numWorkers = workers
	srv.workerQueues = make([]chan QueueItem, workers)
	tcpAssemblers := make([]*TcpAssembler, workers)
	udpAssemblers := make([]*UdpAssembler, workers)

	for i := range workers {
		srv.workerQueues[i] = make(chan QueueItem, 100)

		tcpStreamPool := reassembly.NewStreamPool(tcpStreamFactory)

		tcpAssemblers[i] = reassembly.NewAssembler(tcpStreamPool)
		udpAssemblers[i] = NewUDPAssembler(opts.StreamdocLimit)

		go srv.worker(
			ctx,
			tcpAssemblers[i],
			udpAssemblers[i],
			srv.workerQueues[i],
		)
	}

	srv.tcpAssemblers = tcpAssemblers
	srv.udpAssemblers = udpAssemblers

	return srv
}

// Assembled returns a channel that emits assembled flow entries.
func (s *Service) Assembled() <-chan db.FlowEntry {
	return s.assembledQueue
}

func (a *Service) GetStats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.stats
}

func (a *Service) ProcessPacketSrc(ctx context.Context, src *gopacket.PacketSource, sourceName string) error {

	slog.DebugContext(ctx, "assembler: starting packet processing", "file", sourceName)

	var (
		bytes     int64 = 0     // Total bytes processed
		position  int64 = 0     // Total packets processed, including skipped
		processed int64 = 0     // Packets processed after skipping
		finished        = false // Whether we consumed all packets
	)

	toBeSkipped := a.checkProcessedCount(sourceName)
	slog.DebugContext(ctx, "assembler: skipping packets", "toBeSkipped", toBeSkipped, "file", sourceName)

	defer func() {
		// Update stats and database entry after processing
		// This is done in a deferred function to ensure it runs even if an error occurs

		a.mu.Lock()
		a.stats.Processed += processed
		a.stats.ProcessedBytes += bytes
		a.mu.Unlock()

		slog.Debug("assembler: updating database entry",
			"file", sourceName,
			"position", position,
			"finished", finished,
		)

		err := a.DB.InsertPcap(ctx, db.PcapFile{
			FileName: sourceName,
			Position: position,
			Finished: finished,
		})

		if err != nil {
			slog.Error("assembler: failed to update database entry", "file", sourceName, "err", err)
		} else {
			slog.Debug("assembler: database entry updated successfully", "file", sourceName)
		}
	}()

	nodefrag := false

	for packet := range src.Packets() {
		select {
		case <-a.flushTick.C:
			a.FlushConnections()
		case <-ctx.Done():
			slog.Warn("context cancelled, stopping packet processing", "file", sourceName)
			finished = false
			return ctx.Err()
		default:
		}

		position++
		if position <= toBeSkipped {
			continue
		}

		data := packet.Data()

		processed++
		bytes += int64(len(data))
		shouldStop := a.processPacket(packet, sourceName, nodefrag)
		if shouldStop {
			finished = false
			return fmt.Errorf("processPacket returned true, stopping processing for %s", sourceName)
		}
	}

	if position < toBeSkipped {
		panic(fmt.Sprintf("assembler: position %d is less than toBeSkipped %d for file %s", position, toBeSkipped, sourceName))
	}

	slog.Debug("assembler: finished processing packets",
		"file", sourceName,
		"processed", processed,
		"bytes", bytes,
		"finished", finished,
	)

	finished = true
	return nil
}

// FlushConnections closes and saves connections that are older than the configured timeouts.
func (a *Service) FlushConnections() {
	slog.Debug("Flushing connections", "tcpTimeout", a.ConnectionTcpTimeout, "udpTimeout", a.ConnectionUdpTimeout)
	a.assemblersMu.Lock() // we need to stop every assembler
	defer a.assemblersMu.Unlock()

	thresholdTcp := time.Now().Add(-a.ConnectionTcpTimeout)
	thresholdUdp := time.Now().Add(-a.ConnectionUdpTimeout)
	flushed, closed, discarded := 0, 0, 0

	if a.ConnectionTcpTimeout != 0 {
		for _, assembler := range a.tcpAssemblers {
			localFlushed, localClosed := assembler.FlushCloseOlderThan(thresholdTcp)
			flushed += localFlushed
			closed += localClosed
		}
		discarded = a.defragmenter.DiscardOlderThan(thresholdTcp)
	}

	if flushed != 0 || closed != 0 || discarded != 0 {
		slog.Info("Flushed connections", "flushed", flushed, "closed", closed, "discarded", discarded)
	}

	if a.ConnectionUdpTimeout != 0 {
		for _, udpAssembler := range a.udpAssemblers {
			udpFlows := udpAssembler.CompleteOlderThan(thresholdUdp)
			for _, flow := range udpFlows {
				a.reassemblyCallback(*flow)
			}
			if len(udpFlows) != 0 {
				slog.Info("Assembled UDP flows", "count", len(udpFlows))
			}
		}
	}
}

// checkProcessedCount returns the count of already processed packets for a given file.
func (a *Service) checkProcessedCount(fname string) int64 {
	exists, file := a.DB.GetPcap(context.Background(), fname)
	if exists {
		return file.Position
	}
	return 0 // file not found, return 0 to process all packets
}

// Context implements reassembly.AssemblerContext
type Context struct {
	gopacket.CaptureInfo
	FileName string // FileName is the name of the file being processed
}

func (c Context) GetCaptureInfo() gopacket.CaptureInfo { return c.CaptureInfo }

type QueueItem struct {
	pkt gopacket.Packet
	ctx Context
}

// processPacket handles a single packet: skipping, defragmentation, protocol dispatch (TCP/UDP), and error handling.
// Returns true if processing should stop.
func (a *Service) processPacket(packet gopacket.Packet, fname string, noDefrag bool) (stop bool) {

	// defrag the packet, sequentially
	if !noDefrag {
		complete, err := a.defragPacket(packet)
		if err != nil {
			return true // stop processing due to error
		} else if !complete {
			return false // wait for more fragments
		}
	}

	// Partition the packet to a worker queue based on the network flow
	// This ensures that packets belonging to the same flow are processed by the same worker.
	transport := packet.TransportLayer()
	if transport == nil {
		return false // No transport layer, nothing to process
	}

	flow := transport.TransportFlow()
	queue := a.getWorkerQueue(flow)

	context := Context{packet.Metadata().CaptureInfo, fname}
	queue <- QueueItem{packet, context}

	return false
}

// defragPacket attempts to defragment an IPv4 packet.
//
// Returns true if the packet is complete, false if it is still a fragment,
// and an error if defragmentation fails.
// If the packet is successfully defragmented, it decodes the next protocol layer.
func (a *Service) defragPacket(packet gopacket.Packet) (complete bool, err error) {
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return true, nil // No IPv4 layer found, nothing to defragment
	}

	ip4 := ip4Layer.(*layers.IPv4)
	oldLen := ip4.Length

	newip4, defragErr := a.defragmenter.DefragIPv4(ip4)
	if defragErr != nil {
		slog.Error("Error while de-fragmenting", "err", defragErr)
		return false, defragErr // stop processing due to error
	} else if newip4 == nil {
		// packet fragment, we don't have whole packet yet.
		return false, nil // wait for more fragments
	}

	// If the length of the IPv4 packet has changed after defragmentation,
	// it means we now have a complete packet with a potentially new payload.
	// We need to decode the next protocol layer (e.g., TCP, UDP) from this payload.
	if newip4.Length != oldLen {
		// Attempt to cast the packet to a PacketBuilder, which is required
		// for decoding the next protocol layer.
		pb, ok := packet.(gopacket.PacketBuilder)
		if !ok {
			// Panic if the packet does not implement PacketBuilder.
			// This should not happen in normal operation.
			panic("Packet does not implement gopacket.PacketBuilder, cannot decode next layer")
		}
		// Decode the next layer using the new payload.
		nextDecoder := newip4.NextLayerType()
		err = nextDecoder.Decode(newip4.Payload, pb)
		if err != nil {
			slog.Warn("Error decoding next layer after defragmentation", "err", err)
		}
	}

	return true, nil
}

// reassemblyCallback is called when a flow is completed.
func (a *Service) reassemblyCallback(entry db.FlowEntry) {
	a.assembledQueue <- entry
}

func (a *Service) worker(ctx context.Context, tcpAssembler *TcpAssembler, udpAssembler *UdpAssembler, queue chan QueueItem) {

	lockAndProcess := func(item QueueItem) {
		a.assemblersMu.RLock() // Lock to ensure no flushing while processing
		defer a.assemblersMu.RUnlock()

		transport := item.pkt.TransportLayer()
		if transport == nil {
			return // No transport layer, skip processing
		}

		flow := item.pkt.NetworkLayer().NetworkFlow()
		switch transport.LayerType() {
		case layers.LayerTypeTCP:
			tcpAssembler.AssembleWithContext(flow, transport.(*layers.TCP), item.ctx)
		case layers.LayerTypeUDP:
			udpAssembler.AssembleWithContext(flow, transport.(*layers.UDP), item.ctx)
		}
	}

	for {
		select {
		case <-ctx.Done():
			slog.WarnContext(ctx, "assembler: worker context cancelled, stopping worker")
			return
		case item, ok := <-queue:
			if !ok {
				return // Channel closed, exit the worker
			}

			lockAndProcess(item)
		}
	}
}

func (s *Service) getWorkerQueue(flow gopacket.Flow) chan QueueItem {
	hash := flow.FastHash()
	idx := int(hash % uint64(s.numWorkers))
	return s.workerQueues[idx]
}
