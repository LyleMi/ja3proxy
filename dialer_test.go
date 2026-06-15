package main

import (
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
