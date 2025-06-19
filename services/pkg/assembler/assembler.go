package assembler

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"regexp"
	"time"
	"tulip/pkg/db"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/reassembly"
)

type Service struct {
	Config

	Defragmenter  *ip4defrag.IPv4Defragmenter
	StreamFactory *TcpStreamFactory
	StreamPool    *reassembly.StreamPool

	AssemblerTcp *reassembly.Assembler
	AssemblerUdp *UdpAssembler
}

type Config struct {
	DB            *db.Database   // the database to use for storing flows
	BpfFilter     string         // BPF filter to apply to the pcap handle
	FlushInterval time.Duration  // Interval to flush non-terminated connections
	FlagRegex     *regexp.Regexp // Regex to apply for flagging flows
	TcpLazy       bool           // Lazy decoding for TCP packets
	Experimental  bool           // Experimental features enabled
	NonStrict     bool           // Non-strict mode for TCP stream assembly

	ConnectionTcpTimeout time.Duration
	ConnectionUdpTimeout time.Duration
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
	}
	srv.Config = opts

	onComplete := func(fe db.FlowEntry) { srv.reassemblyCallback(fe) }
	srv.StreamFactory.OnComplete = onComplete

	return srv
}

// TODO; FIXME; RDJ; this is kinda gross, but this is PoC level code
func (s *Service) reassemblyCallback(entry db.FlowEntry) {
	// Parsing HTTP will decode encodings to a plaintext format
	s.ParseHttpFlow(&entry)

	// Apply flag in / flagout
	if s.FlagRegex != nil {
		ApplyFlagTags(&entry, *s.FlagRegex)
	}

	// Finally, insert the new entry
	s.DB.InsertFlow(entry)
}

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

func (s *Service) ProcessPcapHandle(handle *pcap.Handle, fname string) {
	if s.BpfFilter != "" {
		if err := handle.SetBPFFilter(s.BpfFilter); err != nil {
			slog.Error("Failed to set BPF filter", "error", err, "filter", s.BpfFilter)
			return
		}
	}

	processedCount := int64(0)
	processedExists, processedPcap := s.DB.GetPcap(fname)
	if processedExists {
		processedCount = processedPcap.Position
		slog.Info("Skipping already processed packets", "file", fname, "count", processedCount)
	}

	var source *gopacket.PacketSource
	nodefrag := false
	linktype := handle.LinkType()
	switch linktype {
	case layers.LinkTypeIPv4:
		source = gopacket.NewPacketSource(handle, layers.LayerTypeIPv4)
	default:
		source = gopacket.NewPacketSource(handle, linktype)
	}

	source.Lazy = s.TcpLazy
	source.NoCopy = true

	count := int64(0)
	bytes := int64(0)
	lastFlush := time.Now()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	s.FlushConnections()

	for packet := range source.Packets() {
		count++

		// Skip packets that were already processed from this pcap
		if count < processedCount+1 {
			continue
		}

		data := packet.Data()
		bytes += int64(len(data))
		done := false

		// defrag the IPv4 packet if required
		// (TODO; IPv6 will not be defragged)
		ip4Layer := packet.Layer(layers.LayerTypeIPv4)
		if !nodefrag && ip4Layer != nil {

			ip4 := ip4Layer.(*layers.IPv4)
			l := ip4.Length

			newip4, err := s.Defragmenter.DefragIPv4(ip4)
			if err != nil {
				slog.Error("Error while de-fragmenting", "err", err)
				return
			} else if newip4 == nil {
				continue // packet fragment, we don't have whole packet yet.
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
			continue
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

		// Exit if ctx is done
		select {
		case <-signalChan:
			slog.Warn("Caught SIGINT: aborting")
			done = true
		default:
		}

		if done {
			break
		}

		// Try flushing connections here. When using PCAP-over-IP this is required, since it treats whole connection as one pcap.
		// NOTE: PCAP-over-IP: pcapOpenOfflineFile is blocking so we need at least see some packets passing by to get here.
		if s.FlushInterval != 0 && lastFlush.Add(s.FlushInterval).Unix() < time.Now().Unix() {
			s.FlushConnections()
			slog.Info("Processed packets", "count", count-processedCount, "file", fname)
			lastFlush = time.Now()
		}
	}

	slog.Info("Processed packets", "count", count-processedCount, "file", fname)
	s.DB.InsertPcap(fname, count)
}

func (s Service) HandlePcapFile(file *os.File, fname string) {
	var handle *pcap.Handle
	var err error

	if handle, err = pcap.OpenOfflineFile(file); err != nil {
		slog.Error("PCAP OpenOfflineFile error", "err", err)
		return
	}
	defer handle.Close()

	s.ProcessPcapHandle(handle, fname)
}

// HandlePcapStream ingests a PCAP stream from any io.Reader (e.g., TCP connection)
func (s Service) HandlePcapStream(r io.Reader, fname string) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(4)
	if err != nil {
		slog.Error("Failed to peek PCAP magic", "err", err)
		return
	}

	var (
		source   *gopacket.PacketSource
		linktype layers.LinkType
	)

	if len(magic) == 4 && magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a {
		// PCAPNG
		ngReader, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			slog.Error("PCAPNG NewNgReader error", "err", err)
			return
		}
		linktype = ngReader.LinkType()
		source = gopacket.NewPacketSource(ngReader, linktype)
	} else {
		// Classic PCAP
		reader, err := pcapgo.NewReader(br)
		if err != nil {
			slog.Error("PCAP NewReader error", "err", err)
			return
		}
		linktype = reader.LinkType()
		source = gopacket.NewPacketSource(reader, linktype)
	}

	source.Lazy = s.TcpLazy
	source.NoCopy = true

	count := int64(0)
	lastFlush := time.Now()

	for packet := range source.Packets() {
		count++

		data := packet.Data()
		_ = data // could be used for stats

		transport := packet.TransportLayer()
		if transport == nil {
			continue
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

		// Try flushing connections periodically
		if s.FlushInterval != 0 && lastFlush.Add(s.FlushInterval).Unix() < time.Now().Unix() {
			s.FlushConnections()
			slog.Info("Processed packets (stream)", "count", count, "file", fname)
			lastFlush = time.Now()
		}
	}

	slog.Info("Processed packets (stream)", "count", count, "file", fname)
}

func (s Service) HandlePcapUri(fname string) {
	var handle *pcap.Handle
	var err error

	if handle, err = pcap.OpenOffline(fname); err != nil {
		slog.Error("PCAP OpenOffline error", "err", err)
		return
	}
	defer handle.Close()

	s.ProcessPcapHandle(handle, fname)
}
