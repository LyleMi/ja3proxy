package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHandleSOCKS5PlainTCPForwardsBothDirections(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	destConn, upstreamPeer := net.Pipe()
	for _, conn := range []net.Conn{clientConn, serverConn, destConn, upstreamPeer} {
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
	}

	var dialAddr string
	proxy := NewProxy(func(network, addr string) (net.Conn, error) {
		if network != "tcp" {
			t.Fatalf("network = %q, want tcp", network)
		}
		dialAddr = addr
		return destConn, nil
	}, func(sni string, destConn net.Conn, clientConn net.Conn) {
		t.Fatal("SOCKS5 plain TCP should not use TLS MITM connect")
	}, nil)

	done := make(chan struct{})
	go func() {
		proxy.handleSOCKS5(serverConn)
		close(done)
	}()

	writeSOCKS5Greeting(t, clientConn, socks5NoAuth)
	readExact(t, clientConn, []byte{socks5Version, socks5NoAuth})
	writeSOCKS5ConnectRequest(t, clientConn, "example.com", 80)
	readExact(t, clientConn, []byte{socks5Version, socks5Succeeded, socks5Reserved, socks5IPv4, 0, 0, 0, 0, 0, 0})

	if dialAddr != "example.com:80" {
		t.Fatalf("dial addr = %q, want example.com:80", dialAddr)
	}

	serverFirst := []byte("server banner")
	serverFirstWrite := make(chan error, 1)
	go func() {
		_, err := upstreamPeer.Write(serverFirst)
		serverFirstWrite <- err
	}()
	readExact(t, clientConn, serverFirst)
	select {
	case err := <-serverFirstWrite:
		if err != nil {
			t.Fatalf("upstream server-first write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream server-first write timed out")
	}

	request := []byte("plain request")
	if _, err := clientConn.Write(request); err != nil {
		t.Fatalf("client write: %v", err)
	}
	readExact(t, upstreamPeer, request)

	response := []byte("plain response")
	if _, err := upstreamPeer.Write(response); err != nil {
		t.Fatalf("upstream write: %v", err)
	}
	readExact(t, clientConn, response)

	clientConn.Close()
	upstreamPeer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS5 handler did not return after peers closed")
	}
}

func TestHandleSOCKS5TLSUsesConnect(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	destConn, upstreamPeer := net.Pipe()
	for _, conn := range []net.Conn{clientConn, serverConn, destConn, upstreamPeer} {
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
	}

	type connectCall struct {
		sni       string
		firstByte byte
	}
	connectCalls := make(chan connectCall, 1)
	proxy := NewProxy(func(network, addr string) (net.Conn, error) {
		if addr != "secure.example:443" {
			t.Fatalf("dial addr = %q, want secure.example:443", addr)
		}
		return destConn, nil
	}, func(sni string, destConn net.Conn, clientConn net.Conn) {
		buf := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, buf); err != nil {
			t.Errorf("read buffered TLS byte: %v", err)
			return
		}
		connectCalls <- connectCall{sni: sni, firstByte: buf[0]}
	}, nil)

	go proxy.handleSOCKS5(serverConn)

	writeSOCKS5Greeting(t, clientConn, socks5NoAuth)
	readExact(t, clientConn, []byte{socks5Version, socks5NoAuth})
	writeSOCKS5ConnectRequest(t, clientConn, "secure.example", 443)
	readExact(t, clientConn, []byte{socks5Version, socks5Succeeded, socks5Reserved, socks5IPv4, 0, 0, 0, 0, 0, 0})

	if _, err := clientConn.Write([]byte{tlsHandshakeRecord}); err != nil {
		t.Fatalf("client write TLS record byte: %v", err)
	}

	select {
	case call := <-connectCalls:
		if call.sni != "secure.example" {
			t.Fatalf("connect sni = %q, want secure.example", call.sni)
		}
		if call.firstByte != tlsHandshakeRecord {
			t.Fatalf("first buffered byte = %d, want %d", call.firstByte, tlsHandshakeRecord)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for connect call")
	}
}

func TestHandleSOCKS5RejectsUnsupportedAuth(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	if err := clientConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := serverConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set server deadline: %v", err)
	}

	go NewProxy(nil, nil, nil).handleSOCKS5(serverConn)

	writeSOCKS5Greeting(t, clientConn, 0x02)
	readExact(t, clientConn, []byte{socks5Version, socks5NoAcceptable})
}

func TestMixedProxyListenerRoutesHTTPToServer(t *testing.T) {
	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	proxy := NewProxy(nil, nil, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "http://example.com/resource" {
			t.Fatalf("upstream URL = %q, want http://example.com/resource", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Header:     http.Header{"X-Test": {"ok"}},
			Body:       io.NopCloser(strings.NewReader("mixed http")),
		}, nil
	}))
	server := &http.Server{
		Handler: proxy,
	}
	go func() {
		_ = server.Serve(newMixedProxyListener(baseListener, proxy))
	}()
	t.Cleanup(func() {
		_ = server.Close()
	})

	conn, err := net.DialTimeout("tcp", baseListener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial mixed listener: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	_, err = io.WriteString(conn, "GET http://example.com/resource HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatalf("write HTTP proxy request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read HTTP response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if got := resp.Header.Get("X-Test"); got != "ok" {
		t.Fatalf("X-Test = %q, want ok", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "mixed http" {
		t.Fatalf("body = %q, want mixed http", string(body))
	}
}

func writeSOCKS5Greeting(t *testing.T, conn net.Conn, method byte) {
	t.Helper()
	if _, err := conn.Write([]byte{socks5Version, 0x01, method}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
}

func writeSOCKS5ConnectRequest(t *testing.T, conn net.Conn, host string, port uint16) {
	t.Helper()
	request := []byte{socks5Version, socks5Connect, socks5Reserved, socks5Domain, byte(len(host))}
	request = append(request, []byte(host)...)
	request = append(request, byte(port>>8), byte(port))
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("write SOCKS5 connect request: %v", err)
	}
}

func readExact(t *testing.T, conn net.Conn, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read bytes: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("read bytes = %v, want %v", got, want)
	}
}
