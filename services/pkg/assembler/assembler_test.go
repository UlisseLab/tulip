// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package assembler

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
	"tulip/pkg/db"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"go.mongodb.org/mongo-driver/bson"
)

// Helper to create a minimal valid classic PCAP file in memory
func makeValidPcap() []byte {
	buf := &bytes.Buffer{}
	w := pcapgo.NewWriter(buf)
	_ = w.WriteFileHeader(65535, 1) // Ethernet
	// Write a dummy packet
	data := []byte{0xde, 0xad, 0xbe, 0xef}
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(data),
		Length:        len(data),
	}
	_ = w.WritePacket(ci, data)
	return buf.Bytes()
}

// Helper to create a minimal PCAPNG file in memory (just the magic number)
func makeMinimalPcapng() []byte {
	// PCAPNG magic number: 0x0A0D0D0A
	return []byte{0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0}
}

// Helper to create a corrupted file (random bytes)
func makeCorruptedPcap() []byte {
	return []byte{0x01, 0x02, 0x03, 0x04, 0x05}
}

func writeTempFile(t *testing.T, data []byte, suffix string) string {
	t.Helper()
	tmpDir := t.TempDir()
	fname := filepath.Join(tmpDir, "testfile"+suffix)
	if err := os.WriteFile(fname, data, 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return fname
}

type NoopDatabase struct{}

func (n *NoopDatabase) GetFlowList(bson.D) ([]db.FlowEntry, error)     { return nil, nil }
func (n *NoopDatabase) GetTagList() ([]string, error)                  { return nil, nil }
func (n *NoopDatabase) GetSignature(string) (db.Signature, error)      { return db.Signature{}, nil }
func (n *NoopDatabase) SetStar(string, bool) error                     { return nil }
func (n *NoopDatabase) GetFlowDetail(id string) (*db.FlowEntry, error) { return nil, nil }
func (n *NoopDatabase) InsertFlow(db.FlowEntry)                        {}
func (n *NoopDatabase) GetPcap(string) (bool, db.PcapFile)             { return false, db.PcapFile{} }
func (n *NoopDatabase) InsertPcap(db.PcapFile) bool                    { return true }
func (n *NoopDatabase) GetFlagIds() ([]db.FlagIdEntry, error)          { return nil, nil }

func makeTestAssembler() *Service {
	cfg := Config{
		DB:                   &NoopDatabase{},
		TcpLazy:              false,
		Experimental:         false,
		NonStrict:            false,
		FlagRegex:            nil,
		FlushInterval:        0,
		ConnectionTcpTimeout: 0,
		ConnectionUdpTimeout: 0,
	}
	return NewAssemblerService(cfg)
}

func TestHandlePcapUri_DoesNotCrashOnCorruptedOrPcapng(t *testing.T) {
	assembler := makeTestAssembler()

	tests := []struct {
		name    string
		content []byte
	}{
		{"valid_pcap", makeValidPcap()},
		{"minimal_pcapng", makeMinimalPcapng()},
		{"corrupted", makeCorruptedPcap()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fname := writeTempFile(t, tc.content, "."+tc.name)
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("HandlePcapUri panicked on %s: %v", tc.name, r)
				}
			}()
			assembler.HandlePcapUri(t.Context(), fname)
		})
	}
}
