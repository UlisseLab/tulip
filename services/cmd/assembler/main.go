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

package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"tulip/pkg/assembler"
	"tulip/pkg/db"

	"github.com/lmittmann/tint"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var gDB db.MongoDatabase

var rootCmd = &cobra.Command{
	Use:   "assembler",
	Short: "PCAP assembler TCP ingest service",
	Long:  `Assembler watches a directory for incoming PCAP files, processes them, and assembles TCP streams.`,
	Run:   runAssembler,
}

func init() {
	rootCmd.Flags().String("mongo", "localhost:27017", "MongoDB DNS name + port (e.g. mongo:27017)")
	rootCmd.Flags().String("watch-dir", "/tmp/ingestor_ready", "Directory to watch for incoming PCAP files")
	rootCmd.Flags().String("flag", "", "Flag regex, used for flag in/out tagging")
	rootCmd.Flags().String("flush-interval", "15s", "Interval for flushing connections (e.g. 15s, 1m)")
	rootCmd.Flags().Bool("tcp-lazy", false, "Enable lazy decoding for TCP packets")
	rootCmd.Flags().Bool("experimental", false, "Enable experimental features")
	rootCmd.Flags().Bool("nonstrict", false, "Enable non-strict mode for TCP stream assembly")
	rootCmd.Flags().String("connection-timeout", "30s", "Connection timeout for both TCP and UDP flows (e.g. 30s, 1m)")
	rootCmd.Flags().Bool("pperf", false, "Enable performance profiling (experimental)")

	viper.BindPFlag("mongo", rootCmd.Flags().Lookup("mongo"))
	viper.BindPFlag("watch-dir", rootCmd.Flags().Lookup("watch-dir"))
	viper.BindPFlag("flag", rootCmd.Flags().Lookup("flag"))
	viper.BindPFlag("flush-interval", rootCmd.Flags().Lookup("flush-interval"))
	viper.BindPFlag("tcp-lazy", rootCmd.Flags().Lookup("tcp-lazy"))
	viper.BindPFlag("experimental", rootCmd.Flags().Lookup("experimental"))
	viper.BindPFlag("nonstrict", rootCmd.Flags().Lookup("nonstrict"))
	viper.BindPFlag("connection-timeout", rootCmd.Flags().Lookup("connection-timeout"))
	viper.BindPFlag("pperf", rootCmd.Flags().Lookup("pperf"))

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.SetEnvPrefix("TULIP")
}

func runAssembler(cmd *cobra.Command, args []string) {
	// Setup logging
	logger := slog.New(tint.NewHandler(os.Stderr, &tint.Options{
		Level:      slog.LevelInfo,
		TimeFormat: "2006-01-02 15:04:05",
	}))
	slog.SetDefault(logger)

	// Get config from viper
	mongodb := viper.GetString("mongo")
	watchDir := viper.GetString("watch-dir")
	flagRegexStr := viper.GetString("flag")
	flushIntervalStr := viper.GetString("flush-interval")
	tcpLazy := viper.GetBool("tcp-lazy")
	experimental := viper.GetBool("experimental")
	nonstrict := viper.GetBool("nonstrict")
	connectionTimeoutStr := viper.GetString("connection-timeout")
	pperf := viper.GetBool("pperf")

	if pperf {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	// Connect to MongoDB
	dbString := "mongodb://" + mongodb
	slog.Info("Connecting to MongoDB...", slog.String("uri", dbString))

	var err error
	gDB, err = db.ConnectMongo(dbString)
	if err != nil {
		slog.Error("Failed to connect to MongoDB", slog.Any("err", err))
		os.Exit(1)
	}
	slog.Info("Connected to MongoDB")

	slog.Info("Configuring MongoDB database...")
	gDB.ConfigureDatabase()

	// Parse flag regex if provided
	var flagRegex *regexp.Regexp
	if flagRegexStr != "" {
		var err error
		flagRegex, err = regexp.Compile(flagRegexStr)
		if err != nil {
			slog.Error("Invalid flag regex", slog.String("regex", flagRegexStr), slog.Any("err", err))
			os.Exit(1)
		}
	}

	// Parse flush interval
	var flushInterval time.Duration
	if flushIntervalStr != "" {
		var err error
		flushInterval, err = time.ParseDuration(flushIntervalStr)
		if err != nil {
			slog.Error("Invalid flush-interval", slog.String("flush-interval", flushIntervalStr), slog.Any("err", err))
			os.Exit(1)
		}
	}

	// Parse connection timeout
	var connectionTimeout time.Duration
	if connectionTimeoutStr != "" {
		var err error
		connectionTimeout, err = time.ParseDuration(connectionTimeoutStr)
		if err != nil {
			slog.Error("Invalid connection-timeout", slog.String("connection-timeout", connectionTimeoutStr), slog.Any("err", err))
			os.Exit(1)
		}
	}

	// global ctx
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Create assembler service
	flagIdUrl := os.Getenv("FLAGID_URL")
	config := assembler.Config{
		DB:                   &gDB,
		TcpLazy:              tcpLazy,
		Experimental:         experimental,
		NonStrict:            nonstrict,
		FlagRegex:            flagRegex,
		FlushInterval:        flushInterval,
		ConnectionTcpTimeout: connectionTimeout,
		ConnectionUdpTimeout: connectionTimeout,
		FlagIdUrl:            flagIdUrl,
	}
	service := assembler.NewAssemblerService(config)

	// Watch directory for new PCAP files and ingest them
	slog.Info("Watching directory for new PCAP files", slog.String("dir", watchDir))

	// Use polling for simplicity and reliability
	pollInterval := 2 * time.Second
	seen := make(map[string]struct{})

watchLoop:
	for {
		select {
		case <-ctx.Done():
			break watchLoop
		default:
		}

		files, err := os.ReadDir(watchDir)
		if err != nil {
			slog.Error("Failed to read watch directory", slog.Any("err", err))
			time.Sleep(pollInterval)
			continue
		}
		for _, file := range files {
			select {
			case <-ctx.Done():
				break watchLoop
			default:
			}

			if file.IsDir() {
				continue
			}
			name := file.Name()
			if filepath.Ext(name) != ".pcap" {
				continue
			}
			fullPath := filepath.Join(watchDir, name)
			if _, ok := seen[fullPath]; ok {
				continue
			}
			seen[fullPath] = struct{}{}

			slog.Info("Ingesting new PCAP file", slog.String("file", fullPath))
			service.HandlePcapUri(ctx, fullPath)
		}
		time.Sleep(pollInterval)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		slog.Error("Command failed", slog.Any("err", err))
		os.Exit(1)
	}
}
