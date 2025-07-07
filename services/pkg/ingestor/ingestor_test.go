package ingestor

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestSanitizeFilename(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"valid_filename", "valid_filename"},
		{"invalid:filename", "invalid_filename"},
		{"another/invalid\\filename", "another_invalid_filename"},
		{"", ""},
		{"no_special_chars", "no_special_chars"},
		{"123:456/789\\0", "123_456_789_0"},
	}

	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			result := sanitizeFilename(c.input)
			if result != c.expected {
				t.Errorf("sanitizeFilename(%q) = %q; want %q", c.input, result, c.expected)
			}
		})
	}
}

func TestCopyPkt(t *testing.T) {
	// Create a simple Ethernet + IPv4 + TCP packet using gopacket
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    []byte{192, 168, 0, 1},
		DstIP:    []byte{192, 168, 0, 2},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 1234,
		DstPort: 80,
		Seq:     11050,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, eth, ip, tcp, gopacket.Payload([]byte("payload")))
	if err != nil {
		t.Fatalf("Failed to serialize packet: %v", err)
	}
	data := buffer.Bytes()

	// Create a gopacket.Packet with capture info
	captureInfo := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(data),
		Length:        len(data),
	}
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = captureInfo

	// Write packet to a pcapgo.Writer backed by a bytes.Buffer
	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(uint32(len(data)), layers.LinkTypeEthernet); err != nil {
		t.Fatalf("Failed to write PCAP file header: %v", err)
	}

	// Call copyPkt and check for errors
	if err := copyPkt(packet, writer); err != nil {
		t.Fatalf("copyPkt failed: %v", err)
	}

	// Read back the packet from the buffer to verify it was written
	reader, err := pcapgo.NewReader(&buf)
	if err != nil {
		t.Fatalf("Failed to create PCAP reader: %v", err)
	}
	readPktData, ci, err := reader.ReadPacketData()
	if err != nil {
		t.Fatalf("Failed to read packet data: %v", err)
	}

	if ci.CaptureLength != captureInfo.CaptureLength || ci.Length != captureInfo.Length {
		t.Errorf("CaptureInfo mismatch: got %+v, want %+v", ci, captureInfo)
	}
	if !bytes.Equal(readPktData, data) {
		t.Errorf("Packet data mismatch: got %v, want %v", readPktData, data)
	}
}

func BenchmarkCopyPkt(b *testing.B) {
	// Create a simple Ethernet + IPv4 + TCP packet using gopacket
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    []byte{192, 168, 0, 1},
		DstIP:    []byte{192, 168, 0, 2},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 1234,
		DstPort: 80,
		Seq:     11050,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, eth, ip, tcp, gopacket.Payload([]byte("payload")))
	if err != nil {
		b.Fatalf("Failed to serialize packet: %v", err)
	}
	data := buffer.Bytes()

	captureInfo := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(data),
		Length:        len(data),
	}
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = captureInfo

	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(uint32(len(data)), layers.LinkTypeEthernet); err != nil {
		b.Fatalf("Failed to write PCAP file header: %v", err)
	}

	b.SetBytes(int64(len(data)))

	for b.Loop() {
		copyPkt(packet, writer)
	}
}
