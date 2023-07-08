.PHONY: all build-linux build-windows clean

BINARY_NAME=ja3proxy
BINARY_LINUX=$(BINARY_NAME)
BINARY_WINDOWS=$(BINARY_NAME).exe

all: build-linux build-windows

build-linux:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_LINUX)

build-windows:
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_WINDOWS)

clean:
	rm -f $(BINARY_LINUX) $(BINARY_WINDOWS)
