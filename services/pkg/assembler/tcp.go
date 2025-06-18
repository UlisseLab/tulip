// Originally based on code from Google's gopacket repository
// https://github.com/google/gopacket/blob/master/dumpcommand/tcpdump.go

package assembler

import (
	"tulip/pkg/db"

	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

var (
	allowmissinginit = true
	verbose          = false
	debug            = false
	quiet            = true
)

const (
	closeTimeout    time.Duration = time.Hour * 24     // Closing inactive: TODO: from CLI
	timeout         time.Duration = time.Minute * 5    // Pending bytes: TODO: from CLI
	streamdoc_limit int           = 6_000_000 - 0x1000 // 16 MB (6 + (4/3)*6) - some overhead
)

// TcpStreamFactory implements reassembly.StreamFactory for TCP streams.
type TcpStreamFactory struct {
	OnComplete func(db.FlowEntry)
	nonStrict  bool // non-strict mode, used for testing
}

func (f *TcpStreamFactory) New(
	net, transport gopacket.Flow,
	tcp *layers.TCP,
	ac reassembly.AssemblerContext,
) reassembly.Stream {
	source := ac.GetCaptureInfo().AncillaryData[0].(string)
	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: f.nonStrict,
	}
	stream := &TcpStream{
		tcpFSM:    reassembly.NewTCPSimpleFSM(fsmOptions),
		tcpFSMErr: false,

		net:       net,
		transport: transport,

		optChecker: reassembly.NewTCPOptionCheck(),
		source:     source,
		FlowItems:  []db.FlowItem{},
		srcPort:    tcp.SrcPort,
		dstPort:    tcp.DstPort,
		onComplete: f.OnComplete,
		nonStrict:  f.nonStrict,
	}
	return stream
}
