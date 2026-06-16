package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestNewUpstreamDialerDirect(t *testing.T) {
	timeout := 3 * time.Second

	upstream, err := NewUpstreamDialer("", timeout)
	if err != nil {
		t.Fatalf("NewUpstreamDialer() error = %v", err)
	}
	if upstream == nil {
		t.Fatal("expected upstream dialer")
	}

	netDialer, ok := upstream.dialer.(*net.Dialer)
	if !ok {
		t.Fatalf("upstream.dialer = %T, want *net.Dialer", upstream.dialer)
	}
	if netDialer.Timeout != timeout {
		t.Fatalf("net.Dialer timeout = %v, want %v", netDialer.Timeout, timeout)
	}
}

func TestUpstreamDialerDialLocalTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			serverErr <- err
			return
		}

		buf := make([]byte, len("ping"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverErr <- err
			return
		}
		if string(buf) != "ping" {
			serverErr <- fmt.Errorf("payload = %q, want %q", buf, "ping")
			return
		}
		_, err = conn.Write([]byte("pong"))
		serverErr <- err
	}()

	upstream, err := NewUpstreamDialer("", time.Second)
	if err != nil {
		t.Fatalf("NewUpstreamDialer() error = %v", err)
	}

	conn, err := upstream.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write to server: %v", err)
	}
	got := make([]byte, len("pong"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read from server: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("response = %q, want pong", got)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server timed out")
	}
}

func TestNewUpstreamDialerSocksURLValidation(t *testing.T) {
	tests := []struct {
		name      string
		socksAddr string
		wantErr   bool
	}{
		{name: "readme host port", socksAddr: "127.0.0.1:1080"},
		{name: "socks5 url", socksAddr: "socks5://127.0.0.1:1080"},
		{name: "invalid url", socksAddr: "%", wantErr: true},
		{name: "missing host", socksAddr: "socks5://", wantErr: true},
		{name: "unsupported scheme", socksAddr: "http://127.0.0.1:1080", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldTransport := http.DefaultTransport
			t.Cleanup(func() {
				http.DefaultTransport = oldTransport
			})

			upstream, err := NewUpstreamDialer(tt.socksAddr, time.Second)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewUpstreamDialer() error = %v", err)
			}
			if upstream == nil || upstream.dialer == nil {
				t.Fatal("expected upstream dialer")
			}
		})
	}
}

func TestNewUpstreamDialerReadmeSocksAddressSetsHTTPProxy(t *testing.T) {
	oldTransport := http.DefaultTransport
	t.Cleanup(func() {
		http.DefaultTransport = oldTransport
	})

	if _, err := NewUpstreamDialer("127.0.0.1:1080", time.Second); err != nil {
		t.Fatalf("NewUpstreamDialer() error = %v", err)
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("http.DefaultTransport = %T, want *http.Transport", http.DefaultTransport)
	}
	proxyURL, err := transport.Proxy(&http.Request{})
	if err != nil {
		t.Fatalf("transport.Proxy() error = %v", err)
	}
	if proxyURL == nil {
		t.Fatal("expected proxy URL")
	}
	if proxyURL.Scheme != "socks5" {
		t.Fatalf("proxy URL scheme = %q, want socks5", proxyURL.Scheme)
	}
	if proxyURL.Host != "127.0.0.1:1080" {
		t.Fatalf("proxy URL host = %q, want 127.0.0.1:1080", proxyURL.Host)
	}
}

func TestParseSocksURLPreservesAuthAndDefaultsScheme(t *testing.T) {
	parsedURL, err := parseSocksURL("user:pass@127.0.0.1:1080")
	if err != nil {
		t.Fatalf("parseSocksURL() error = %v", err)
	}
	if parsedURL.Scheme != "socks5" {
		t.Fatalf("scheme = %q, want socks5", parsedURL.Scheme)
	}
	if parsedURL.Host != "127.0.0.1:1080" {
		t.Fatalf("host = %q, want 127.0.0.1:1080", parsedURL.Host)
	}
	if got := parsedURL.User.Username(); got != "user" {
		t.Fatalf("username = %q, want user", got)
	}
	password, ok := parsedURL.User.Password()
	if !ok {
		t.Fatal("password missing")
	}
	if password != "pass" {
		t.Fatalf("password = %q, want pass", password)
	}
}
