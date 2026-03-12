NAME = vuls-exporter

.PHONY: build test vet lint clean

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags="-extldflags=-static -s -w" -o dist/$(NAME) ./cmd/

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf dist/
