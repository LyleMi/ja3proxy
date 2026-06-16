package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestE2EHTTPProxyRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("upstream method = %q, want POST", r.Method)
		}
		if r.URL.String() != "/v1/resource?x=1" {
			t.Fatalf("upstream URL = %q, want /v1/resource?x=1", r.URL.String())
		}
		if got := r.Header.Get("X-Client-Test"); got != "plain-http" {
			t.Fatalf("upstream X-Client-Test = %q, want plain-http", got)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		if string(body) != "request through proxy" {
			t.Fatalf("upstream body = %q, want request through proxy", body)
		}

		w.Header().Set("X-Upstream-Test", "ok")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("proxied response"))
	}))
	t.Cleanup(upstream.Close)

	proxyServer := httptest.NewServer(NewProxy(nil, nil, nil))
	t.Cleanup(proxyServer.Close)

	client := newProxyHTTPClient(t, proxyServer.URL, nil)
	req, err := http.NewRequest(
		http.MethodPost,
		upstream.URL+"/v1/resource?x=1",
		strings.NewReader("request through proxy"),
	)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Client-Test", "plain-http")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	if got := resp.Header.Get("X-Upstream-Test"); got != "ok" {
		t.Fatalf("X-Upstream-Test = %q, want ok", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read proxied response: %v", err)
	}
	if string(body) != "proxied response" {
		t.Fatalf("response body = %q, want proxied response", body)
	}
}

func TestE2EHTTPSConnectProxyRequest(t *testing.T) {
	restoreTestTLSState(t)
	configureTestCA(t)

	const targetHost = "target.test"
	upstreamSNI := make(chan string, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Fatal("upstream request was not received over TLS")
		}
		if r.Method != http.MethodGet {
			t.Fatalf("upstream method = %q, want GET", r.Method)
		}
		if r.URL.String() != "/secure?via=proxy" {
			t.Fatalf("upstream URL = %q, want /secure?via=proxy", r.URL.String())
		}
		if got := r.Header.Get("X-Client-Test"); got != "https-connect" {
			t.Fatalf("upstream X-Client-Test = %q, want https-connect", got)
		}

		w.Header().Set("X-Upstream-TLS", r.TLS.NegotiatedProtocol)
		_, _ = w.Write([]byte("secure proxied response"))
	}))
	upstream.TLS = &tls.Config{
		Certificates: []tls.Certificate{localTLSCertificate(t)},
		NextProtos:   []string{"http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			upstreamSNI <- hello.ServerName
			return nil, nil
		},
	}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	_, upstreamPort, err := net.SplitHostPort(upstreamURL.Host)
	if err != nil {
		t.Fatalf("split upstream host: %v", err)
	}
	targetAddr := net.JoinHostPort(targetHost, upstreamPort)
	dialer := &net.Dialer{Timeout: 2 * time.Second}

	proxy := NewProxy(func(network, addr string) (net.Conn, error) {
		if network != "tcp" {
			return nil, fmt.Errorf("network = %q, want tcp", network)
		}
		if addr != targetAddr {
			return nil, fmt.Errorf("addr = %q, want %q", addr, targetAddr)
		}
		return dialer.Dial(network, upstreamURL.Host)
	}, tunnelConnect, nil)
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	roots := x509.NewCertPool()
	roots.AddCert(CA.x509Cert)
	client := newProxyHTTPClient(t, proxyServer.URL, &tls.Config{
		RootCAs: roots,
	})
	targetURL := "https://" + targetAddr + "/secure?via=proxy"
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Client-Test", "https-connect")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy HTTPS request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("X-Upstream-TLS"); got != "http/1.1" {
		t.Fatalf("upstream negotiated protocol = %q, want http/1.1", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read proxied HTTPS response: %v", err)
	}
	if string(body) != "secure proxied response" {
		t.Fatalf("response body = %q, want secure proxied response", body)
	}

	select {
	case got := <-upstreamSNI:
		if got != targetHost {
			t.Fatalf("upstream SNI = %q, want %q", got, targetHost)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream SNI")
	}
}

func newProxyHTTPClient(t *testing.T, proxyServerURL string, tlsConfig *tls.Config) *http.Client {
	t.Helper()

	proxyURL, err := url.Parse(proxyServerURL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		TLSClientConfig:     tlsConfig,
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: 2 * time.Second,
	}
	t.Cleanup(transport.CloseIdleConnections)

	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
}

func configureTestCA(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	Config.Debug = false
	Config.TLSClient = utls.HelloGolang.Client
	Config.TLSVersion = utls.HelloGolang.Version
	Config.Cert = filepath.Join(dir, "ca.pem")
	Config.Key = filepath.Join(dir, "ca-key.pem")

	if err := generateCA(); err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}
	if err := generateSessionKey(); err != nil {
		t.Fatalf("generateSessionKey() error = %v", err)
	}
}

func restoreTestTLSState(t *testing.T) {
	t.Helper()

	oldConfig := Config
	oldCA := CA
	oldSessionKey := SessionKey
	t.Cleanup(func() {
		Config = oldConfig
		CA = oldCA
		SessionKey = oldSessionKey
	})
}
