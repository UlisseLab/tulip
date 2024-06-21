### BASE BUILDER

FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git make build-base libpcap-dev
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY ./ ./
RUN go build ./cmd/enricher && go build ./cmd/assembler

### ENRICHER

FROM alpine:3.12 as enricher
WORKDIR /app
COPY --from=builder /build/enricher ./
CMD ["./enricher"]

### ASSEMBLER

FROM alpine:3.9 as assembler
RUN apk add --no-cache libpcap-dev
WORKDIR /app
COPY --from=builder /build/assembler ./
CMD ["./assembler"]
