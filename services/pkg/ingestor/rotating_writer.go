// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

package ingestor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// RotatingPCAPWriter captures packets from a network connection and writes them to PCAP files.
//
// It writes packets to files in a temporary directory, then, after interval duration, it rotates the file
// by closing it, moving it to a destination directory, and creating a new file.
type RotatingPCAPWriter struct {
	conn     net.Conn
	tempDir  string
	destDir  string
	clientID string
	interval time.Duration
}

// NewRotatingPCAPWriter creates a new rotatingWriterPCAP.
func NewRotatingPCAPWriter(
	conn net.Conn,
	tempDir, destDir, clientID string,
	interval time.Duration,
) *RotatingPCAPWriter {
	return &RotatingPCAPWriter{
		conn:     conn,
		tempDir:  tempDir,
		destDir:  destDir,
		clientID: clientID,
		interval: interval,
	}
}

// Start begins reading packets from the connection and writing them to rotated PCAP/PCAPNG files.
func (rw *RotatingPCAPWriter) Start(ctx context.Context) error {
	var (
		currentReader *pcapgo.Reader
		currentFile   *os.File
		currentWriter *pcapgo.Writer
		err           error
	)

	rotate := func() {
		currentFile.Close()
		rw.moveToDest(currentFile.Name())
		currentFile = nil
		currentWriter = nil
	}

	// Open the connection as a PCAP file
	currentReader, err = pcapgo.NewReader(rw.conn)
	if err != nil {
		return fmt.Errorf("failed to create PCAP reader: %w", err)
	}

	snaplen := currentReader.Snaplen()
	linktype := currentReader.LinkType()
	packetSource := gopacket.NewPacketSource(currentReader, linktype)

	timer := time.NewTimer(rw.interval)
	defer timer.Stop()

rotationLoop:
	for {
		now := time.Now().Format("2006-01-02T15-04-05")
		fname := fmt.Sprintf("pcap_%s_%s.pcap", rw.clientID, now)
		fpath := filepath.Join(rw.tempDir, fname)

		currentFile, err = os.Create(fpath)
		if err != nil {
			return fmt.Errorf("failed to create file for rotation: %w", err)
		}

		currentWriter = pcapgo.NewWriter(currentFile)
		if err := currentWriter.WriteFileHeader(snaplen, linktype); err != nil {
			currentFile.Close()
			return fmt.Errorf("failed to write PCAP header: %w", err)
		}

	packetsLoop:
		for {
			select {
			case <-timer.C:
				// time to rotate
				timer.Reset(rw.interval)
				break packetsLoop

			case <-ctx.Done():
				// context cancelled, exit ingestion loop
				break rotationLoop

			case pkt, ok := <-packetSource.Packets():
				if !ok {
					// channel closed, exit rotation loop
					break rotationLoop
				}

				err := copyPkt(pkt, currentWriter)
				if err != nil {
					return fmt.Errorf("failed to copy packet: %w", err)
				}
			}
		}

		// If we reach here, it means we either rotated or the context was cancelled
		rotate()

		if ctx.Err() != nil {
			return fmt.Errorf("context cancelled: %w", ctx.Err())
		}
	}

	// rotate last time if we exit the loop
	rotate()
	slog.Info("Finished writing PCAP files", slog.String("client", rw.clientID))
	return nil
}

// moveToDest moves a file from the temp directory to the destination directory.
func (rw *RotatingPCAPWriter) moveToDest(srcPath string) {
	base := filepath.Base(srcPath)
	destPath := filepath.Join(rw.destDir, base)
	err := os.Rename(srcPath, destPath)
	if err != nil {
		// try to copy and remove if rename fails
		err = copyFile(srcPath, destPath)
		if err != nil {
			slog.Error("Failed to move PCAP file", slog.String("src", srcPath), slog.String("dest", destPath), slog.Any("err", err))
			return
		}
	}
	slog.Info("Rotated PCAP file", slog.String("file", base), slog.String("dest", destPath))
}

func copyFile(srcPath, destPath string) error {
	input, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer input.Close()

	output, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer output.Close()

	if _, err := io.Copy(output, input); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	return nil
}

func copyPkt(src gopacket.Packet, dst *pcapgo.Writer) error {
	ci := src.Metadata().CaptureInfo
	data := src.Data()

	return dst.WritePacket(ci, data)
}
