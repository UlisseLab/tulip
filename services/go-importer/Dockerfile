ARG ALPINE_VERSION=3.22
ARG GO_VERSION=1.24

### BASE BUILDER
FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder
RUN apk add --no-cache git make build-base libpcap-dev

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY ./ ./

RUN go build -v -o enricher ./cmd/enricher \
    && go build -v -o assembler ./cmd/assembler

### BASE IMAGE
FROM alpine:${ALPINE_VERSION} AS base

### ENRICHER
FROM base AS enricher

WORKDIR /app
COPY --from=builder /build/enricher ./
CMD ["./enricher"]

### ASSEMBLER
FROM base AS assembler
RUN apk add --no-cache libpcap-dev

WORKDIR /app
COPY --from=builder /build/assembler ./
CMD ["./assembler"]
