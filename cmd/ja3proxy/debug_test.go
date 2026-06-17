package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
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

func TestDebugWriterWriteEmptyForwardsToConn(t *testing.T) {
	conn := &recordingConn{}

	writer := DebugWriter{Name: "test", Conn: conn}
	n, err := writer.Write([]byte{})
	if err != nil {
		t.Fatalf("DebugWriter.Write(empty) error = %v", err)
	}
	if n != 0 {
		t.Fatalf("DebugWriter.Write(empty) n = %d, want 0", n)
	}
	if len(conn.writes) != 1 {
		t.Fatalf("underlying Write calls = %d, want 1", len(conn.writes))
	}
	if len(conn.writes[0]) != 0 {
		t.Fatalf("underlying Write data length = %d, want 0", len(conn.writes[0]))
	}
}

func TestDebugWriterWriteForwardsBinaryData(t *testing.T) {
	reader, writerConn := net.Pipe()
	defer reader.Close()
	defer writerConn.Close()

	writer := DebugWriter{Name: "test", Conn: writerConn}
	input := []byte{0x00, 0xff, 0x10, 0x7f, 'A'}
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
	if !bytes.Equal(got, input) {
		t.Fatalf("forwarded data = %v, want %v", got, input)
	}
}

func TestDebugJunctionForwardsBothDirectionsAndCloses(t *testing.T) {
	destConn, destPeer := net.Pipe()
	clientConn, clientPeer := net.Pipe()
	defer destPeer.Close()
	defer clientPeer.Close()

	deadline := time.Now().Add(time.Second)
	for _, conn := range []net.Conn{destConn, destPeer, clientConn, clientPeer} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatalf("SetDeadline() error = %v", err)
		}
	}

	done := make(chan struct{})
	go func() {
		debugJunction(destConn, clientConn)
		close(done)
	}()

	assertForwarded := func(name string, from net.Conn, to net.Conn, input []byte) {
		t.Helper()

		writeDone := make(chan error, 1)
		go func() {
			_, err := from.Write(input)
			writeDone <- err
		}()

		got := make([]byte, len(input))
		if _, err := io.ReadFull(to, got); err != nil {
			t.Fatalf("%s ReadFull() error = %v", name, err)
		}
		if err := <-writeDone; err != nil {
			t.Fatalf("%s Write() error = %v", name, err)
		}
		if !bytes.Equal(got, input) {
			t.Fatalf("%s forwarded data = %q, want %q", name, got, input)
		}
	}

	assertForwarded("client to dest", clientPeer, destPeer, []byte("from client"))
	assertForwarded("dest to client", destPeer, clientPeer, []byte("from dest"))

	if err := clientPeer.Close(); err != nil {
		t.Fatalf("clientPeer.Close() error = %v", err)
	}
	if err := destPeer.Close(); err != nil {
		t.Fatalf("destPeer.Close() error = %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("debugJunction did not return after peers closed")
	}
}

func TestDebugJunctionReturnsWhenOneSideCloses(t *testing.T) {
	destConn, destPeer := net.Pipe()
	clientConn, clientPeer := net.Pipe()
	defer destConn.Close()
	defer destPeer.Close()
	defer clientConn.Close()
	defer clientPeer.Close()

	deadline := time.Now().Add(time.Second)
	for _, conn := range []net.Conn{destConn, destPeer, clientConn, clientPeer} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatalf("SetDeadline() error = %v", err)
		}
	}

	done := make(chan struct{})
	go func() {
		debugJunction(destConn, clientConn)
		close(done)
	}()

	if err := clientPeer.Close(); err != nil {
		t.Fatalf("clientPeer.Close() error = %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("debugJunction did not return after one side closed")
	}
}

type recordingConn struct {
	net.Conn
	writes [][]byte
}

func (conn *recordingConn) Write(data []byte) (int, error) {
	conn.writes = append(conn.writes, append([]byte(nil), data...))
	return len(data), nil
}
