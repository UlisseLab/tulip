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
	"net"
	"os"
	"strings"
	"time"

	"log/slog"

	"github.com/lmittmann/tint"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"

	"tulip/pkg/db"
)

var gDb db.MongoDatabase

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

	viper.BindPFlag("mongo", rootCmd.Flags().Lookup("mongo"))
	viper.BindPFlag("flowbits", rootCmd.Flags().Lookup("flowbits"))
	viper.BindPFlag("redis", rootCmd.Flags().Lookup("redis"))

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
	gDb, err = db.ConnectMongo(dbString)
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
type suricataLog struct {
	flow      db.FlowID
	signature db.Signature
}

func handleEveLine(json string, tagFlowbits bool) (bool, error) {
	if !gjson.Valid(json) {
		return false, errors.New("Invalid json in eve line")
	}

	src_port := gjson.Get(json, "src_port")
	src_ip := gjson.Get(json, "src_ip")
	dst_port := gjson.Get(json, "dest_port")
	dst_ip := gjson.Get(json, "dest_ip")
	start_time := gjson.Get(json, "flow.start")

	sig_msg := gjson.Get(json, "alert.signature")
	sig_id := gjson.Get(json, "alert.signature_id")
	sig_action := gjson.Get(json, "alert.action")
	tag := ""
	jtag := gjson.Get(json, "alert.metadata.tag.0")
	flowbits := gjson.Get(json, "metadata.flowbits")

	src_ip_str := net.ParseIP(src_ip.String()).String()
	dst_ip_str := net.ParseIP(dst_ip.String()).String()

	start_time_obj, _ := time.Parse("2006-01-02T15:04:05.999999999-0700", start_time.String())

	if jtag.Exists() {
		tag = jtag.String()
	}

	if !(sig_action.Exists() || (flowbits.Exists() && tagFlowbits)) {
		return false, nil
	}

	id := db.FlowID{
		Src_port: int(src_port.Int()),
		Src_ip:   src_ip_str,
		Dst_port: int(dst_port.Int()),
		Dst_ip:   dst_ip_str,
		Time:     start_time_obj,
	}

	id_rev := db.FlowID{
		Dst_port: int(src_port.Int()),
		Dst_ip:   src_ip_str,
		Src_port: int(dst_port.Int()),
		Src_ip:   dst_ip_str,
		Time:     start_time_obj,
	}

	ret := false
	if sig_action.Exists() {
		sig := db.Signature{
			ID:     int(sig_id.Int()),
			Msg:    sig_msg.String(),
			Action: sig_action.String(),
			Tag:    tag,
		}
		ret = gDb.AddSignatureToFlow(id, sig, WINDOW)
		ret = ret || gDb.AddSignatureToFlow(id_rev, sig, WINDOW)
	}

	if !(flowbits.Exists() && tagFlowbits) {
		return ret, nil
	}

	tags := []string{}
	flowbits.ForEach(func(key, value gjson.Result) bool {
		tags = append(tags, value.String())
		return true
	})

	ret = gDb.AddTagsToFlow(id, tags, WINDOW)
	ret = ret || gDb.AddTagsToFlow(id_rev, tags, WINDOW)
	return ret, nil
}

func watchRedis(redisUrl string, tagFlowbits bool) {
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

	for {
		lines, err := rdb.RPopCount(context.TODO(), "suricata", 100).Result()
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
			_, err = handleEveLine(line, tagFlowbits)
			if err != nil {
				slog.Error("Failed to handle eve line", slog.String("line", line), slog.Any("err", err))
				continue
			}
			processed++
		}

		slog.Info("Processed lines from redis", slog.Int("processed", processed))
	}
}
