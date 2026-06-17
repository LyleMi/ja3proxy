package main

import (
	"bufio"
	"bytes"
	"errors"
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

func TestHandleSOCKS5RejectsUnsupportedCommand(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	if err := clientConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := serverConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set server deadline: %v", err)
	}

	proxy := NewProxy(func(network, addr string) (net.Conn, error) {
		t.Fatalf("dial should not be called for unsupported command")
		return nil, nil
	}, nil, nil)
	go proxy.handleSOCKS5(serverConn)

	writeSOCKS5Greeting(t, clientConn, socks5NoAuth)
	readExact(t, clientConn, []byte{socks5Version, socks5NoAuth})
	writeSOCKS5Request(t, clientConn, 0x02, socks5Reserved, socks5Domain, []byte("example.com"), 80)
	readExact(t, clientConn, []byte{socks5Version, socks5CommandFail, socks5Reserved, socks5IPv4, 0, 0, 0, 0, 0, 0})
}

func TestHandleSOCKS5RejectsInvalidRequestHeader(t *testing.T) {
	tests := []struct {
		name    string
		version byte
		rsv     byte
	}{
		{
			name:    "invalid version",
			version: 0x04,
			rsv:     socks5Reserved,
		},
		{
			name:    "invalid reserved byte",
			version: socks5Version,
			rsv:     0x01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			writeSOCKS5Greeting(t, clientConn, socks5NoAuth)
			readExact(t, clientConn, []byte{socks5Version, socks5NoAuth})
			request := []byte{tt.version, socks5Connect, tt.rsv, socks5Domain, byte(len("example.com"))}
			request = append(request, []byte("example.com")...)
			request = append(request, 0, 80)
			if _, err := clientConn.Write(request); err != nil {
				t.Fatalf("write SOCKS5 request: %v", err)
			}
			readExact(t, clientConn, []byte{socks5Version, socks5AddressFail, socks5Reserved, socks5IPv4, 0, 0, 0, 0, 0, 0})
		})
	}
}

func TestReadSOCKS5Request(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
		want    socks5Request
	}{
		{
			name:    "IPv4 address",
			request: socks5RequestBytes(socks5Version, socks5Connect, socks5Reserved, socks5IPv4, []byte{192, 0, 2, 10}, 8080),
			want: socks5Request{
				command: socks5Connect,
				host:    "192.0.2.10",
				port:    8080,
			},
		},
		{
			name:    "IPv6 address",
			request: socks5RequestBytes(socks5Version, socks5Connect, socks5Reserved, socks5IPv6, net.ParseIP("2001:db8::1").To16(), 443),
			want: socks5Request{
				command: socks5Connect,
				host:    "2001:db8::1",
				port:    443,
			},
		},
		{
			name:    "domain address with non-connect command",
			request: socks5RequestBytes(socks5Version, 0x02, socks5Reserved, socks5Domain, []byte("example.com"), 53),
			want: socks5Request{
				command: 0x02,
				host:    "example.com",
				port:    53,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readSOCKS5Request(bufio.NewReader(bytes.NewReader(tt.request)))
			if err != nil {
				t.Fatalf("readSOCKS5Request() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("readSOCKS5Request() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestReadSOCKS5RequestErrors(t *testing.T) {
	tests := []struct {
		name    string
		request []byte
	}{
		{
			name:    "short header",
			request: []byte{socks5Version, socks5Connect, socks5Reserved},
		},
		{
			name:    "invalid version",
			request: socks5RequestBytes(0x04, socks5Connect, socks5Reserved, socks5Domain, []byte("example.com"), 80),
		},
		{
			name:    "invalid reserved byte",
			request: socks5RequestBytes(socks5Version, socks5Connect, 0x01, socks5Domain, []byte("example.com"), 80),
		},
		{
			name:    "unsupported address type",
			request: []byte{socks5Version, socks5Connect, socks5Reserved, 0x05},
		},
		{
			name:    "missing port",
			request: []byte{socks5Version, socks5Connect, socks5Reserved, socks5IPv4, 192, 0, 2, 10, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := readSOCKS5Request(bufio.NewReader(bytes.NewReader(tt.request))); err == nil {
				t.Fatal("readSOCKS5Request() error = nil, want error")
			}
		})
	}
}

func TestReadSOCKS5Address(t *testing.T) {
	tests := []struct {
		name string
		atyp byte
		data []byte
		want string
	}{
		{
			name: "IPv4 address",
			atyp: socks5IPv4,
			data: []byte{203, 0, 113, 7},
			want: "203.0.113.7",
		},
		{
			name: "IPv6 address",
			atyp: socks5IPv6,
			data: net.ParseIP("2001:db8::2").To16(),
			want: "2001:db8::2",
		},
		{
			name: "domain address",
			atyp: socks5Domain,
			data: append([]byte{byte(len("example.org"))}, []byte("example.org")...),
			want: "example.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readSOCKS5Address(bufio.NewReader(bytes.NewReader(tt.data)), tt.atyp)
			if err != nil {
				t.Fatalf("readSOCKS5Address() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("readSOCKS5Address() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadSOCKS5AddressErrors(t *testing.T) {
	tests := []struct {
		name string
		atyp byte
		data []byte
	}{
		{
			name: "short IPv4 address",
			atyp: socks5IPv4,
			data: []byte{192, 0, 2},
		},
		{
			name: "short IPv6 address",
			atyp: socks5IPv6,
			data: net.ParseIP("2001:db8::3").To16()[:15],
		},
		{
			name: "missing domain length",
			atyp: socks5Domain,
			data: nil,
		},
		{
			name: "empty domain",
			atyp: socks5Domain,
			data: []byte{0},
		},
		{
			name: "short domain",
			atyp: socks5Domain,
			data: []byte{3, 'a', 'b'},
		},
		{
			name: "unsupported address type",
			atyp: 0x05,
			data: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := readSOCKS5Address(bufio.NewReader(bytes.NewReader(tt.data)), tt.atyp); err == nil {
				t.Fatal("readSOCKS5Address() error = nil, want error")
			}
		})
	}
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

func TestMixedProxyListenerAddrAndClose(t *testing.T) {
	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	listener := newMixedProxyListener(baseListener, NewProxy(nil, nil, nil))
	if listener.Addr().String() != baseListener.Addr().String() {
		t.Fatalf("Addr() = %q, want %q", listener.Addr().String(), baseListener.Addr().String())
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept() error = %v, want %v", err, net.ErrClosed)
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
	request := socks5RequestBytes(socks5Version, socks5Connect, socks5Reserved, socks5Domain, []byte(host), port)
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("write SOCKS5 connect request: %v", err)
	}
}

func writeSOCKS5Request(t *testing.T, conn net.Conn, command byte, rsv byte, atyp byte, address []byte, port uint16) {
	t.Helper()
	if _, err := conn.Write(socks5RequestBytes(socks5Version, command, rsv, atyp, address, port)); err != nil {
		t.Fatalf("write SOCKS5 request: %v", err)
	}
}

func socks5RequestBytes(version byte, command byte, rsv byte, atyp byte, address []byte, port uint16) []byte {
	request := []byte{version, command, rsv, atyp}
	if atyp == socks5Domain {
		request = append(request, byte(len(address)))
	}
	request = append(request, address...)
	request = append(request, byte(port>>8), byte(port))
	return request
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
