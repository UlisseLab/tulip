// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/lmittmann/tint"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func sanitizeFilename(s string) string {
	r := []rune(s)
	for i, c := range r {
		if c == ':' || c == '/' || c == '\\' {
			r[i] = '_'
		}
	}
	return string(r)
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "ingestor",
		Short: "PCAP ingestor service",
		Long:  "Listens for incoming PCAP-over-IP connections, saves files to a temp folder, and rotates them to a destination folder every N seconds.",
		Run:   runIngestor,
	}

	rootCmd.Flags().String("listen", "0.0.0.0:9999", "TCP address to listen on for incoming PCAP streams")
	rootCmd.Flags().String("temp-dir", "/tmp/ingestor_tmp", "Directory to temporarily store incoming PCAP files")
	rootCmd.Flags().String("dest-dir", "/tmp/ingestor_ready", "Directory to move rotated PCAP files for downstream processing")
	rootCmd.Flags().Duration("rotate-interval", time.Minute, "Interval for rotating files from temp to destination folder (e.g. 1m, 30s)")

	viper.BindPFlag("listen", rootCmd.Flags().Lookup("listen"))
	viper.BindPFlag("temp-dir", rootCmd.Flags().Lookup("temp-dir"))
	viper.BindPFlag("dest-dir", rootCmd.Flags().Lookup("dest-dir"))
	viper.BindPFlag("rotate-interval", rootCmd.Flags().Lookup("rotate-interval"))

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.SetEnvPrefix("TULIP")

	logger := slog.New(tint.NewHandler(os.Stderr, &tint.Options{
		Level:      slog.LevelInfo,
		TimeFormat: "2006-01-02 15:04:05",
	}))
	slog.SetDefault(logger)

	if err := rootCmd.Execute(); err != nil {
		slog.Error("Command failed", slog.Any("err", err))
		os.Exit(1)
	}
}

func runIngestor(cmd *cobra.Command, args []string) {
	var (
		cfgListenAddr     = viper.GetString("listen")
		cfgTempDir        = viper.GetString("temp-dir")
		cfgDestDir        = viper.GetString("dest-dir")
		cfgRotateInterval = viper.GetDuration("rotate-interval")
	)

	slog.Info("Starting ingestor service",
		slog.String("listen", cfgListenAddr),
		slog.String("temp-dir", cfgTempDir),
		slog.String("dest-dir", cfgDestDir),
		slog.Duration("rotate-interval", cfgRotateInterval),
	)

	if err := os.MkdirAll(cfgTempDir, 0o755); err != nil {
		slog.Error("Failed to create temp directory", slog.Any("err", err))
		os.Exit(1)
	}
	if err := os.MkdirAll(cfgDestDir, 0o755); err != nil {
		slog.Error("Failed to create destination directory", slog.Any("err", err))
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", cfgListenAddr)
	if err != nil {
		slog.Error("Failed to start TCP server", slog.Any("err", err))
		os.Exit(1)
	}
	defer ln.Close()

	slog.Info("Listening for incoming PCAP connections...", slog.String("address", cfgListenAddr))

	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Error("Failed to accept connection", slog.Any("err", err))
			continue
		}
		go handlePcapConnection(conn, cfgTempDir, cfgDestDir, cfgRotateInterval)
	}
}

// handlePcapConnection handles a single incoming PCAP-over-IP connection.
func handlePcapConnection(conn net.Conn, tempDir, destDir string, rotateInterval time.Duration) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()
	clientID := sanitizeFilename(clientAddr)
	slog.Info("Accepted new PCAP connection", slog.String("client", clientAddr))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rw := NewRotatingWriterPCAP(conn, tempDir, destDir, clientID, rotateInterval)
	rw.Start(ctx)

	slog.Info("Finished ingesting PCAP connection", slog.String("client", clientAddr))
}
