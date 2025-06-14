package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"time"

	"github.com/charmbracelet/log"
	"github.com/redis/go-redis/v9"
	"github.com/tidwall/gjson"

	"tulip/pkg/db"
)

var (
	eveFile      = flag.String("eve", "", "Eve file to watch for suricata's tags")
	mongodb      = flag.String("mongo", "", "MongoDB dns name + port (e.g. mongo:27017)")
	tagFlowbits  = flag.Bool("flowbits", true, "Tag flows with their flowbits")
	rescanPeriod = flag.Int("t", 30, "rescan period (in seconds).")
	redisConn    = flag.String("redis", "", "Redis connection string")
)

var gDb db.Database

const WINDOW = 5000 // ms

func main() {
	flag.Parse()

	// If no mongo DB was supplied, try the env variable
	if *mongodb == "" {
		*mongodb = os.Getenv("TULIP_MONGO")
		// if that didn't work, just guess a reasonable default
		if *mongodb == "" {
			*mongodb = "localhost:27017"
		}
	}

	if *redisConn == "" {
		*redisConn = os.Getenv("REDIS_URL")
	}

	dbString := "mongodb://" + *mongodb
	gDb = db.ConnectMongo(dbString)

	if *eveFile != "" {
		watchEve(*eveFile)
	} else if *redisConn != "" {
		watchRedis(*redisConn)
	} else {
		log.Warn("No eve file or redis connection supplied. Exiting.")
		log.Warn("Usage: enricher -eve <eve_file> -mongo <mongo_db> [-t <rescan_period>] [-flowbits]")
		log.Warn("Usage: enricher -redis <redis_url> -mongo <mongo_db> [-t <rescan_period>] [-flowbits]")
		os.Exit(1)
	}
}

func watchEve(eve_file string) {
	// Do the initial scan
	log.Info("Parsing initial eve contents...")
	ratchet := updateEve(eve_file, 0)

	log.Info("Monitoring eve file: ", eve_file)
	stat, err := os.Stat(eve_file)
	prevSize := int64(0)
	if err == nil {
		prevSize = stat.Size()
	}

	for {
		time.Sleep(time.Duration(*rescanPeriod) * time.Second)

		new_stat, err := os.Stat(eve_file)
		if err != nil {
			log.Errorf("Failed to open the eve file with error: %v", err)
			continue
		}

		if new_stat.Size() > prevSize {
			log.Info("Eve file was updated. New size: %d", new_stat.Size())
			ratchet = updateEve(eve_file, ratchet)
		}
		prevSize = new_stat.Size()

	}

}

// The eve file was just written to, let's parse some logs!
func updateEve(eve_file string, ratchet int64) int64 {

	// Open a handle to the eve file
	eve_handle, err := os.Open(eve_file)
	if err != nil {
		log.Errorf("Failed to open the eve file")
		return ratchet
	}
	eve_handle.Seek(ratchet, 0)
	eveReader := bufio.NewReader(eve_handle)
	defer eve_handle.Close()

	log.Info("Start scanning eve file @ ", ratchet)

	// iterate over each line in the file
	for {
		line, err := eveReader.ReadString('\n')
		if err != nil {
			// This is most likely to be EOF, which is fine
			// TODO; check the error code and log if it is something else
			break
		}
		// Line parsing failed. Probably incomplete?
		applied, err := handleEveLine(line)
		if err == nil {
			// parsing this line failed. It may be incomplete for a couple reasons.
			// * First, we might have caught the file in the middle of a write.
			//   That's fine, next pass we'll get new data
			// * The second case is worse, this line may just be corrupt. In that case,
			//   we need to skip over it, after verifying that we're not in case 1.

			// For now, I'm just gonna solve this by ratchetting to the last successfully
			// applied rule. This will cause us to rescan a few lines needlessly, but I'm okay with that.
			if applied {
				ratchet += int64(len(line))
			}
		}
	}

	// Roll the eve handle back to the last successfully applied rule, so it can continue there
	// next time this function is called.
	return ratchet
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

func handleEveLine(json string) (bool, error) {
	if !gjson.Valid(json) {
		return false, errors.New("Invalid json in eve line")
	}

	// TODO; error check this
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

	// canonicalize the IP address notation to make sure it matches what the assembler entered
	// into the database.
	// TODO; just assuming these are all valid for now. Should be fine, since this is coming from
	// suricata and is not _really_ user controlled. Might panic in some obscure case though.
	src_ip_str := net.ParseIP(src_ip.String()).String()
	dst_ip_str := net.ParseIP(dst_ip.String()).String()

	// TODO; Double check this, might be broken for non-UTC?
	start_time_obj, _ := time.Parse("2006-01-02T15:04:05.999999999-0700", start_time.String())

	if jtag.Exists() {
		tag = jtag.String()
	}

	// If no action was taken, there's no need for us to do anything with this line.
	if !(sig_action.Exists() || (flowbits.Exists() && *tagFlowbits)) {
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

		// TODO; use one, sensible query instead of just trying both cases
		ret = gDb.AddSignatureToFlow(id, sig, WINDOW)
		ret = ret || gDb.AddSignatureToFlow(id_rev, sig, WINDOW)
	}

	if !(flowbits.Exists() && *tagFlowbits) {
		return ret, nil
	}

	tags := []string{}
	flowbits.ForEach(func(key, value gjson.Result) bool {
		tags = append(tags, value.String())
		return true // keep iterating
	})

	// TODO; use one, sensible query instead of just trying both cases
	ret = gDb.AddTagsToFlow(id, tags, WINDOW)
	ret = ret || gDb.AddTagsToFlow(id_rev, tags, WINDOW)
	return ret, nil
}

func watchRedis(redisUrl string) {
	opt, err := redis.ParseURL(redisUrl)
	if err != nil {
		log.Errorf("Failed to parse redis url: %v", err)
		return
	}

	rdb := redis.NewClient(opt)
	defer func() {
		err := rdb.Close()
		if err != nil {
			log.Errorf("Failed to close redis connection: %v", err)
		}
	}()

	log.Info("Connected to redis")

	// connect to "suricata" list and ingest the data
	for {
		lines, err := rdb.RPopCount(context.TODO(), "suricata", 100).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				time.Sleep(1 * time.Second)
				continue
			}

			log.Warnf("Failed to pop from redis: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		processed := 0
		for _, line := range lines {
			_, err = handleEveLine(line)
			if err != nil {
				log.Errorf(`Failed to handle eve line "%s": %s`, line, err)
				continue
			}
			processed++
		}

		log.Infof("Processed %d lines from redis", processed)
	}
}
