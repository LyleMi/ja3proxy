package main

import (
	"io"
	"net"
	"testing"
)

func TestDebugWriterWriteForwardsData(t *testing.T) {
	reader, writerConn := net.Pipe()
	defer reader.Close()
	defer writerConn.Close()

	writer := DebugWriter{Name: "test", Conn: writerConn}
	input := []byte("GET / HTTP/1.1\r\n\r\n")
	writeDone := make(chan struct {
		n   int
		err error
	}, 1)

	go func() {
		n, err := writer.Write(input)
		writeDone <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()

	got := make([]byte, len(input))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}

	result := <-writeDone
	if result.err != nil {
		t.Fatalf("DebugWriter.Write() error = %v", result.err)
	}
	if result.n != len(input) {
		t.Fatalf("DebugWriter.Write() n = %d, want %d", result.n, len(input))
	}
	if string(got) != string(input) {
		t.Fatalf("forwarded data = %q, want %q", got, input)
	}
}
