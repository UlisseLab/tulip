// SPDX-FileCopyrightText: 2022 - 2023 Rick de Jager <rickdejager99@gmail.com>
// SPDX-FileCopyrightText: 2022 erdnaxe <erdnaxe@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 Max Groot <19346100+MaxGroot@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 liskaant <liskaant@gmail.com>
// SPDX-FileCopyrightText: 2024 - 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"log/slog"

	"github.com/lmittmann/tint"
	"github.com/panjf2000/ants/v2"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"

	"tulip/pkg/db"
)

var gDb db.Database

const WINDOW = 5000 // ms

func main() {
	rootCmd := &cobra.Command{
		Use:   "enricher",
		Short: "Enrich flows with Suricata tags from Redis",
		Run:   runEnricher,
	}

	rootCmd.Flags().String("mongo", "localhost:27017", "MongoDB dns name + port (e.g. mongo:27017)")
	rootCmd.Flags().Bool("flowbits", true, "Tag flows with their flowbits")
	rootCmd.Flags().String("redis", "", "Redis connection string")

	_ = viper.BindPFlag("mongo", rootCmd.Flags().Lookup("mongo"))
	_ = viper.BindPFlag("flowbits", rootCmd.Flags().Lookup("flowbits"))
	_ = viper.BindPFlag("redis", rootCmd.Flags().Lookup("redis"))

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

func runEnricher(cmd *cobra.Command, args []string) {
	var (
		mongodb     = viper.GetString("mongo")
		tagFlowbits = viper.GetBool("flowbits")
		redisConn   = viper.GetString("redis")
	)

	if redisConn == "" {
		slog.Warn("No redis connection supplied. Exiting.")
		os.Exit(1)
	}

	var err error
	dbString := "mongodb://" + mongodb
	slog.Info("Connecting to MongoDB", slog.String("uri", dbString))
	gDb, err = db.NewMongoDatabase(context.TODO(), dbString)
	if err != nil {
		slog.Error("Failed to connect to MongoDB", slog.Any("err", err))
		os.Exit(1)
	}

	watchRedis(redisConn, tagFlowbits)
}

/*
	{
		"timestamp": "2022-05-17T19:39:57.283547+0000",
		"flow_id": 1905964640824789,
		"in_iface": "eth0",
		"event_type": "alert",
		"src_ip": "131.155.9.104",
		"src_port": 53604,
		"dest_ip": "165.232.89.44",
		"dest_port": 1337,
		"proto": "TCP",
		"pkt_src": "stream (flow timeout)",
		"alert": {
			"action": "allowed",
			"gid": 1,
			"signature_id": 1338,
			"rev": 1,
			"signature": "Detected too many A's (smart)",
			"category": "",
			"severity": 3
		},
		"app_proto": "failed",
		"flow": {
			"pkts_toserver": 6,
			"pkts_toclient": 6,
			"bytes_toserver": 437,
			"bytes_toclient": 477,
			"start": "2022-05-17T19:37:02.978389+0000"
		}
	}
*/

func handleEveLine(json string, tagFlowbits bool) (stop bool, error error) {
	if !gjson.Valid(json) {
		return false, fmt.Errorf("invalid JSON: %s", json)
	}

	var (
		srcPort   = gjson.Get(json, "src_port")
		srcIp     = gjson.Get(json, "src_ip")
		dstPort   = gjson.Get(json, "dest_port")
		dstIp     = gjson.Get(json, "dest_ip")
		startTime = gjson.Get(json, "flow.start")

		sigId     = gjson.Get(json, "alert.signature_id")
		sigMsg    = gjson.Get(json, "alert.signature")
		sigAction = gjson.Get(json, "alert.action")
		jtag      = gjson.Get(json, "alert.metadata.tag.0")

		flowbits = gjson.Get(json, "metadata.flowbits")

		src_ip_str = net.ParseIP(srcIp.String()).String()
		dst_ip_str = net.ParseIP(dstIp.String()).String()
	)

	start_time_obj, _ := time.Parse("2006-01-02T15:04:05.999999999-0700", startTime.String())

	tag := ""
	if jtag.Exists() {
		tag = jtag.String()
	}

	if !sigAction.Exists() && (!flowbits.Exists() || !tagFlowbits) {
		return false, nil // No action to take
	}

	id := db.FlowID{
		SrcPort: int(srcPort.Int()),
		SrcIp:   src_ip_str,
		DstPort: int(dstPort.Int()),
		DstIp:   dst_ip_str,
		Time:    start_time_obj,
	}

	id_rev := db.FlowID{
		DstPort: int(srcPort.Int()),
		DstIp:   src_ip_str,
		SrcPort: int(dstPort.Int()),
		SrcIp:   dst_ip_str,
		Time:    start_time_obj,
	}

	if sigAction.Exists() {
		sig := db.SuricataSig{
			ID:     int(sigId.Int()),
			Msg:    sigMsg.String(),
			Action: sigAction.String(),
			Tag:    tag,
		}
		err := gDb.AddSignatureToFlow(context.Background(), id, sig, WINDOW)
		if err != nil {
			return false, fmt.Errorf("failed to add signature to flow: %w", err)
		}

		err = gDb.AddSignatureToFlow(context.Background(), id_rev, sig, WINDOW)
		if err != nil {
			return false, fmt.Errorf("failed to add signature to flow: %w", err)
		}
	}

	if !flowbits.Exists() || !tagFlowbits {
		return false, nil // No flowbits to process
	}

	tags := []string{}
	flowbits.ForEach(func(key, value gjson.Result) bool {
		tags = append(tags, value.String())
		return true
	})

	// Add tags to tag collection
	err := gDb.InsertTags(context.Background(), tags)
	if err != nil {
		return false, fmt.Errorf("failed to insert tags: %w", err)
	}

	err = gDb.AddTagsToFlow(context.Background(), id, tags, WINDOW)
	if err != nil {
		return false, fmt.Errorf("failed to add tags to flow: %w", err)
	}
	err = gDb.AddTagsToFlow(context.Background(), id_rev, tags, WINDOW)
	if err != nil {
		return false, fmt.Errorf("failed to add tags to reverse flow: %w", err)
	}

	return false, nil
}

func watchRedis(redisUrl string, tagFlowbits bool) {
	var (
		workers    = 4   // Number of goroutines to use for processing
		redisBatch = 100 // Number of lines to read from redis at once
	)

	opt, err := redis.ParseURL(redisUrl)
	if err != nil {
		slog.Error("Failed to parse redis url", slog.Any("err", err))
		return
	}

	slog.Info("Connecting to redis", slog.String("url", redisUrl))
	rdb := redis.NewClient(opt)
	defer func() {
		err := rdb.Close()
		if err != nil {
			slog.Error("Failed to close redis connection", slog.Any("err", err))
		}
	}()

	slog.Info("Connected to redis")

	linesProcessingCtx, cancelLinesProcessing := context.WithCancel(context.Background())
	defer cancelLinesProcessing()

	pool, err := ants.NewPoolWithFuncGeneric(workers, func(line string) {
		stop, err := handleEveLine(line, tagFlowbits)
		if err != nil {
			slog.Error("Failed to handle eve line", slog.String("line", line), slog.Any("err", err))
		}

		if stop {
			slog.Info("Stopping enricher due to stop signal")
			cancelLinesProcessing()
		}
	}, ants.WithPreAlloc(true))

	if err != nil {
		slog.Error("Failed to create goroutine pool", slog.Any("err", err))
		return
	}

lineLoop:
	for {
		select {
		case <-linesProcessingCtx.Done():
			break lineLoop
		default:
		}

		lines, err := rdb.RPopCount(context.TODO(), "suricata", redisBatch).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				time.Sleep(1 * time.Second)
				continue
			}
			slog.Warn("Failed to pop from redis", slog.Any("err", err))
			time.Sleep(1 * time.Second)
			continue
		}

		processed := 0
		for _, line := range lines {
			err := pool.Invoke(line)
			if err != nil {
				slog.Error("Failed to process line", slog.String("line", line), slog.Any("err", err))
				continue
			}
			processed++
		}

		slog.Info("Processed lines from redis", slog.Int("processed", processed))
	}

	pool.Release()
	slog.Info("Enricher stopped")
}
