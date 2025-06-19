# SPDX-FileCopyrightText: 2024 - 2025 Eyad Issa <eyadlorenzo@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-only

ARG ALPINE_VERSION=3.22

FROM alpine:${ALPINE_VERSION}
RUN apk add --no-cache suricata

COPY run.sh /run.sh
RUN chmod +x /run.sh

WORKDIR /suricata

CMD ["/run.sh"]
