VERSION ?= $(shell git describe --tags --always --dirty --match="v*" 2> /dev/null || echo "v1.0.0")

.phony: linux-secret-helper windows-secret-helper

all: linux-secret-helper windows-secret-helper

linux-secret-helper:
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.Version=${VERSION}" -o bin/releases/linux-amd64/secret-helper main.go
	tar -C bin/releases/linux-amd64 -cvzf bin/releases/linux-amd64-${VERSION}.tgz secret-helper 

windows-secret-helper:
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X main.Version=${VERSION}" -o bin/releases/windows-amd64/secret-helper.exe main.go
	tar -C bin/releases/windows-amd64 -cvzf bin/releases/windows-amd64-${VERSION}.tgz secret-helper.exe
