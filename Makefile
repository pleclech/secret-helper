.phony: linux-secret-helper windows-secret-helper

all: linux-secret-helper windows-secret-helper

linux-secret-helper:
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bin/releases/linux-amd64/secret-helper main.go

windows-secret-helper:
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o bin/releases/windows-amd64/secret-helper.exe main.go
