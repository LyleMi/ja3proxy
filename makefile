.PHONY: all build-linux build-windows clean

BINARY_NAME=ja3proxy
BINARY_DIR=bin
BINARY_LINUX=$(BINARY_DIR)/$(BINARY_NAME)
BINARY_WINDOWS=$(BINARY_DIR)/$(BINARY_NAME).exe

all: build-linux build-windows

$(BINARY_DIR):
	mkdir -p $(BINARY_DIR)

build-linux: $(BINARY_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_LINUX) ./cmd/ja3proxy

build-windows: $(BINARY_DIR)
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_WINDOWS) ./cmd/ja3proxy

clean:
	rm -f $(BINARY_LINUX) $(BINARY_WINDOWS)
