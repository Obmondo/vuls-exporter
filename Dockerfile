FROM golang:1.26-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-extldflags=-static -s -w" -o vuls-exporter ./cmd/

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/vuls-exporter /vuls-exporter

ENTRYPOINT ["/vuls-exporter"]
