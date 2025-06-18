package main

import (
	"fmt"
	"regexp"

	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"tulip/pkg/assembler"
	"tulip/pkg/db"

	"github.com/lmittmann/tint"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var gDB db.Database

var rootCmd = &cobra.Command{
	Use:   "assembler",
	Short: "PCAP assembler TCP ingest service",
	Long: `A network traffic assembler that listens for incoming TCP connections.
Each connection is interpreted as a PCAP stream and ingested into MongoDB.`,
	Run: runAssembler,
}

func init() {
	rootCmd.Flags().String("mongo", "localhost:27017", "MongoDB DNS name + port (e.g. mongo:27017)")
	rootCmd.Flags().String("listen", "localhost:9999", "TCP address to listen on for incoming PCAP streams (e.g. :1337, 127.0.0.1:9000)")
	rootCmd.Flags().String("flag", "", "Flag regex, used for flag in/out tagging")
	rootCmd.Flags().String("flush-interval", "15s", "Interval for flushing connections (e.g. 15s, 1m)")
	rootCmd.Flags().Bool("tcp-lazy", false, "Enable lazy decoding for TCP packets")
	rootCmd.Flags().Bool("experimental", false, "Enable experimental features")
	rootCmd.Flags().Bool("nonstrict", false, "Enable non-strict mode for TCP stream assembly")
	rootCmd.Flags().String("connection-timeout", "30s", "Connection timeout for both TCP and UDP flows (e.g. 30s, 1m)")

	viper.BindPFlag("mongo", rootCmd.Flags().Lookup("mongo"))
	viper.BindPFlag("listen", rootCmd.Flags().Lookup("listen"))
	viper.BindPFlag("flag", rootCmd.Flags().Lookup("flag"))
	viper.BindPFlag("flush-interval", rootCmd.Flags().Lookup("flush-interval"))
	viper.BindPFlag("tcp-lazy", rootCmd.Flags().Lookup("tcp-lazy"))
	viper.BindPFlag("experimental", rootCmd.Flags().Lookup("experimental"))
	viper.BindPFlag("nonstrict", rootCmd.Flags().Lookup("nonstrict"))
	viper.BindPFlag("connection-timeout", rootCmd.Flags().Lookup("connection-timeout"))

	viper.AutomaticEnv()
	viper.SetEnvPrefix("TULIP")
}

func runAssembler(cmd *cobra.Command, args []string) {
	// Get all viper flags
	var (
		mongodb              = viper.GetString("mongo")
		listenAddr           = viper.GetString("listen")
		flagRegexStr         = viper.GetString("flag")
		flushIntervalStr     = viper.GetString("flush-interval")
		tcpLazy              = viper.GetBool("tcp-lazy")
		experimental         = viper.GetBool("experimental")
		nonstrict            = viper.GetBool("nonstrict")
		connectionTimeoutStr = viper.GetString("connection-timeout")
	)

	// Setup logging
	logger := slog.New(tint.NewHandler(os.Stderr, &tint.Options{
		Level:      slog.LevelInfo,
		TimeFormat: time.TimeOnly,
	}))
	slog.SetDefault(logger)

	// Connect to MongoDB
	dbString := "mongodb://" + mongodb
	slog.Info("Connecting to MongoDB...", slog.String("uri", dbString))
	gDB = db.ConnectMongo(dbString)
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

	// Create assembler service
	config := assembler.Config{
		DB:                   &gDB,
		TcpLazy:              tcpLazy,
		Experimental:         experimental,
		NonStrict:            nonstrict,
		FlagRegex:            flagRegex,
		FlushInterval:        flushInterval,
		ConnectionTcpTimeout: connectionTimeout,
		ConnectionUdpTimeout: connectionTimeout,
	}
	service := assembler.NewAssemblerService(config)

	// Start TCP server
	slog.Info("Starting TCP server", slog.String("address", listenAddr))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		slog.Error("Failed to start TCP server", slog.Any("err", err))
		os.Exit(1)
	}
	defer ln.Close()

	// Handle graceful shutdown via context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		slog.Warn("Received shutdown signal, stopping server...")
		cancel()
		ln.Close()
	}()

	var connID int64 = 0
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				break
			default:
				slog.Error("Failed to accept connection", slog.Any("err", err))
				continue
			}
			break
		}
		id := atomic.AddInt64(&connID, 1)
		go handlePcapConnectionCtx(ctx, service, conn, id)
	}

	slog.Info("Server stopped")
}

func handlePcapConnectionCtx(ctx context.Context, service *assembler.Service, conn net.Conn, id int64) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()
	fname := fmt.Sprintf("tcpclient-%s-%d-%d", clientAddr, id, time.Now().Unix())
	slog.Info("Accepted new PCAP connection", slog.String("client", clientAddr), slog.String("fname", fname))

	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Recovered from panic in PCAP handler", slog.Any("err", r), slog.String("client", clientAddr), slog.String("fname", fname))
			}
			close(done)
		}()
		// Ingest the stream using HandlePcapStream
		service.HandlePcapStream(conn, fname)
	}()

	select {
	case <-ctx.Done():
		slog.Warn("Context canceled, closing connection", slog.String("client", clientAddr), slog.String("fname", fname))
		conn.Close()
	case <-done:
		slog.Info("Finished ingesting PCAP connection", slog.String("client", clientAddr), slog.String("fname", fname))
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		slog.Error("Command failed", slog.Any("err", err))
		os.Exit(1)
	}
}
