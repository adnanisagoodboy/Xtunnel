.PHONY: build build-server build-agent clean test run-server run-agent

GOFLAGS := -mod=mod
GONOSUMDB := *
GOPROXY := direct

build: build-server build-agent

build-server:
	GONOSUMDB=$(GONOSUMDB) GOPROXY=$(GOPROXY) go build $(GOFLAGS) \
		-ldflags="-X main.version=1.0.0" \
		-o bin/xtunnel-server ./server/cmd

build-agent:
	GONOSUMDB=$(GONOSUMDB) GOPROXY=$(GOPROXY) go build $(GOFLAGS) \
		-ldflags="-X main.version=1.0.0" \
		-o bin/xtunnel ./agent/cmd

build-linux:
	GOOS=linux GOARCH=amd64 GONOSUMDB=$(GONOSUMDB) GOPROXY=$(GOPROXY) \
		go build $(GOFLAGS) -o bin/xtunnel-server-linux ./server/cmd
	GOOS=linux GOARCH=amd64 GONOSUMDB=$(GONOSUMDB) GOPROXY=$(GOPROXY) \
		go build $(GOFLAGS) -o bin/xtunnel-linux ./agent/cmd

build-macos:
	GOOS=darwin GOARCH=arm64 GONOSUMDB=$(GONOSUMDB) GOPROXY=$(GOPROXY) \
		go build $(GOFLAGS) -o bin/xtunnel-server-macos ./server/cmd
	GOOS=darwin GOARCH=arm64 GONOSUMDB=$(GONOSUMDB) GOPROXY=$(GOPROXY) \
		go build $(GOFLAGS) -o bin/xtunnel-macos ./agent/cmd

build-windows:
	GOOS=windows GOARCH=amd64 GONOSUMDB=$(GONOSUMDB) GOPROXY=$(GOPROXY) \
		go build $(GOFLAGS) -o bin/xtunnel-server.exe ./server/cmd
	GOOS=windows GOARCH=amd64 GONOSUMDB=$(GONOSUMDB) GOPROXY=$(GOPROXY) \
		go build $(GOFLAGS) -o bin/xtunnel.exe ./agent/cmd

clean:
	rm -rf bin/

test:
	GONOSUMDB=$(GONOSUMDB) GOPROXY=$(GOPROXY) go test $(GOFLAGS) ./...

run-server:
	go run $(GOFLAGS) ./server/cmd --config configs/server.json

run-agent:
	go run $(GOFLAGS) ./agent/cmd http 3000 --server localhost:7000

vet:
	GONOSUMDB=$(GONOSUMDB) GOPROXY=$(GOPROXY) go vet $(GOFLAGS) ./...
