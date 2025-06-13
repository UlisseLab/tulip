ARG ALPINE_VERSION=3.22

FROM alpine:${ALPINE_VERSION}
RUN apk add --no-cache suricata socat

COPY run.sh /run.sh
RUN chmod +x /run.sh

WORKDIR /suricata

CMD ["/run.sh"]
