// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"log/slog"
	"os"
	"strings"
	"time"
	"tulip/pkg/ingestor"

	"github.com/lmittmann/tint"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "ingestor",
		Short: "PCAP ingestor service",
		Long:  "Listens for incoming PCAP-over-IP connections, saves files to a temp folder, and rotates them to a destination folder every N seconds.",
		Run:   runIngestor,
	}

	rootCmd.Flags().String("listen", "0.0.0.0:9999", "TCP address to listen on for incoming PCAP streams")
	rootCmd.Flags().String("temp-dir", "", "directory to temporarily store incoming PCAP files, if not specified a temp directory will be created")
	rootCmd.Flags().String("dest-dir", "", "directory to move rotated PCAP files for downstream processing")
	rootCmd.Flags().Duration("rotate-interval", time.Minute, "interval for rotating files from temp to destination folder (e.g. 1m, 30s)")

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

	if cfgTempDir == "" {
		var err error
		cfgTempDir, err = os.MkdirTemp("", "tulip-ingestor-")
		if err != nil {
			slog.Error("Failed to create temporary directory", slog.Any("err", err))
			os.Exit(1)
		}
	}

	if cfgDestDir == "" {
		slog.Error("Destination directory must be specified. Use --dest-dir or TULIP_DEST_DIR environment variable.")
		os.Exit(1)
	}

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

	ing := &ingestor.Ingestor{
		TmpDir:         cfgTempDir,
		DestDir:        cfgDestDir,
		RotateInterval: cfgRotateInterval,
	}

	err := ing.Serve(cfgListenAddr)
	if err != nil {
		slog.Error("ingestor stopped with error", slog.Any("err", err))
		os.Exit(1)
	}
}
