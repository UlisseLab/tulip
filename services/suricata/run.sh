#!/usr/bin/env sh

SURICATA_PARAMS="-c /etc/suricata/suricata.yaml \
  -r /dev/stdin
  --pcap-file-continuous \
  --set runmode=single \
  --set outputs.0.fast.enabled=false \
  --set outputs.1.eve-log.enabled=true \
  --set outputs.1.eve-log.filetype=redis
  --set outputs.1.eve-log.redis.server=${REDIS_HOST} \
  --set outputs.1.eve-log.redis.port=${REDIS_PORT} \
  --set outputs.7.stats.enabled=false"

set -x

socat tcp:${PCAP_OVER_IP} - | suricata ${SURICATA_PARAMS} -v
