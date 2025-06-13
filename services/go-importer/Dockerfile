### BASE BUILDER
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git make build-base libpcap-dev
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY ./ ./
RUN go build ./cmd/enricher && go build ./cmd/assembler

### BASE IMAGE

FROM alpine:3.12 as base

### ENRICHER
FROM base as enricher

WORKDIR /app
COPY --from=builder /build/enricher ./
CMD ["./enricher"]

### ASSEMBLER
FROM base as assembler

RUN apk add --no-cache libpcap-dev
WORKDIR /app
COPY --from=builder /build/assembler ./
CMD ["./assembler"]
