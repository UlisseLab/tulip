#!/usr/bin/env sh

# SPDX-FileCopyrightText: 2024 - 2025 Eyad Issa <eyadlorenzo@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

suricata \
  -v \
  -c /etc/suricata/suricata.yaml \
  -r ${WATCH_DIR} \
  --pcap-file-continuous \
  --set "runmode=single" \
  --set "outputs.0.fast.enabled=false" \
  --set "outputs.1.eve-log.enabled=true" \
  --set "outputs.1.eve-log.filetype=redis" \
  --set "outputs.1.eve-log.redis.server=${REDIS_HOST}" \
  --set "outputs.1.eve-log.redis.port=${REDIS_PORT}" \
  --set outputs.7.stats.enabled=false
