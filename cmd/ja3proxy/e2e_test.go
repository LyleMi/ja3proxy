package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
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

func TestE2EHTTPSConnectProxyChangesJA3Fingerprint(t *testing.T) {
	restoreTestTLSState(t)
	configureTestCA(t)
	Config.TLSClient = utls.HelloFirefox_63.Client
	Config.TLSVersion = utls.HelloFirefox_63.Version

	const targetHost = "target.test"
	upstreamAddr, upstreamResults := newJA3CaptureTLSServer(t)
	_, upstreamPort, err := net.SplitHostPort(upstreamAddr)
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
		return dialer.Dial(network, upstreamAddr)
	}, tunnelConnect, nil)
	proxyServer := httptest.NewServer(proxy)
	t.Cleanup(proxyServer.Close)

	roots := x509.NewCertPool()
	roots.AddCert(CA.x509Cert)
	client := newProxyHTTPClient(t, proxyServer.URL, &tls.Config{
		RootCAs: roots,
	})
	resp, err := client.Get("https://" + targetAddr + "/ja3")
	if err != nil {
		t.Fatalf("proxy HTTPS request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read proxied HTTPS response: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("response body = %q, want ok", body)
	}

	result := receiveJA3CaptureResult(t, upstreamResults)
	if result.err != nil {
		t.Fatalf("upstream TLS server error = %v", result.err)
	}
	if result.serverName != targetHost {
		t.Fatalf("upstream SNI = %q, want %q", result.serverName, targetHost)
	}
	if result.requestURI != "/ja3" {
		t.Fatalf("upstream request URI = %q, want /ja3", result.requestURI)
	}

	expectedFirefoxJA3 := expectedUTLSJA3Fingerprint(t, utls.HelloFirefox_63, targetHost, []string{"http/1.1"})
	expectedGolangJA3 := expectedCryptoTLSJA3Fingerprint(t, targetHost, []string{"http/1.1"})
	if result.ja3Fingerprint != expectedFirefoxJA3 {
		t.Fatalf("upstream JA3 = %s (%s), want Firefox_63 %s", result.ja3Fingerprint, result.ja3, expectedFirefoxJA3)
	}
	if result.ja3Fingerprint == expectedGolangJA3 {
		t.Fatalf("upstream JA3 still matched Golang fingerprint %s", expectedGolangJA3)
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

type ja3CaptureResult struct {
	ja3            string
	ja3Fingerprint string
	requestURI     string
	serverName     string
	err            error
}

type bufferedConn struct {
	net.Conn
	reader *bytes.Reader
}

func (conn *bufferedConn) Read(p []byte) (int, error) {
	if conn.reader.Len() > 0 {
		return conn.reader.Read(p)
	}
	return conn.Conn.Read(p)
}

func newJA3CaptureTLSServer(t *testing.T) (string, <-chan ja3CaptureResult) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on local TCP address: %v", err)
	}
	t.Cleanup(func() {
		listener.Close()
	})

	results := make(chan ja3CaptureResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			results <- ja3CaptureResult{err: err}
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			results <- ja3CaptureResult{err: err}
			return
		}

		rawClientHello, err := readTLSRecord(conn)
		if err != nil {
			results <- ja3CaptureResult{err: err}
			return
		}
		ja3, fingerprint, err := ja3FromRawClientHello(rawClientHello)
		if err != nil {
			results <- ja3CaptureResult{err: err}
			return
		}

		var serverName string
		tlsConn := tls.Server(&bufferedConn{
			Conn:   conn,
			reader: bytes.NewReader(rawClientHello),
		}, &tls.Config{
			Certificates: []tls.Certificate{localTLSCertificate(t)},
			NextProtos:   []string{"http/1.1"},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				serverName = hello.ServerName
				return nil, nil
			},
		})
		defer tlsConn.Close()

		if err := tlsConn.Handshake(); err != nil {
			results <- ja3CaptureResult{ja3: ja3, ja3Fingerprint: fingerprint, err: err}
			return
		}
		req, err := http.ReadRequest(bufio.NewReader(tlsConn))
		if err != nil {
			results <- ja3CaptureResult{ja3: ja3, ja3Fingerprint: fingerprint, serverName: serverName, err: err}
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()

		if _, err := io.WriteString(tlsConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"); err != nil {
			results <- ja3CaptureResult{ja3: ja3, ja3Fingerprint: fingerprint, serverName: serverName, requestURI: req.URL.RequestURI(), err: err}
			return
		}

		results <- ja3CaptureResult{
			ja3:            ja3,
			ja3Fingerprint: fingerprint,
			requestURI:     req.URL.RequestURI(),
			serverName:     serverName,
		}
	}()

	return listener.Addr().String(), results
}

func receiveJA3CaptureResult(t *testing.T, results <-chan ja3CaptureResult) ja3CaptureResult {
	t.Helper()

	select {
	case result := <-results:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for JA3 capture server")
	}
	return ja3CaptureResult{}
}

func readTLSRecord(conn net.Conn) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 22 {
		return nil, fmt.Errorf("TLS record type = %d, want handshake", header[0])
	}

	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	body := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

func expectedUTLSJA3Fingerprint(t *testing.T, clientHelloID utls.ClientHelloID, serverName string, nextProtos []string) string {
	t.Helper()

	uconn := utls.UClient(&net.TCPConn{}, &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         nextProtos,
	}, clientHelloID)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("build %s ClientHello: %v", clientHelloID.Str(), err)
	}

	_, fingerprint, err := ja3FromRawClientHello(prependTLSRecordHeader(uconn.HandshakeState.Hello.Raw))
	if err != nil {
		t.Fatalf("calculate %s JA3: %v", clientHelloID.Str(), err)
	}
	return fingerprint
}

func expectedCryptoTLSJA3Fingerprint(t *testing.T, serverName string, nextProtos []string) string {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	deadline := time.Now().Add(2 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set server deadline: %v", err)
	}

	handshakeDone := make(chan struct{})
	go func() {
		defer close(handshakeDone)
		_ = tls.Client(clientConn, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			NextProtos:         nextProtos,
		}).Handshake()
	}()

	rawClientHello, err := readTLSRecord(serverConn)
	if err != nil {
		t.Fatalf("read crypto/tls ClientHello: %v", err)
	}
	_, fingerprint, err := ja3FromRawClientHello(rawClientHello)
	if err != nil {
		t.Fatalf("calculate crypto/tls JA3: %v", err)
	}

	serverConn.Close()
	select {
	case <-handshakeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("crypto/tls handshake did not return after server close")
	}
	return fingerprint
}

func prependTLSRecordHeader(handshake []byte) []byte {
	header := []byte{
		22,
		0x03, 0x01,
		byte(len(handshake) >> 8), byte(len(handshake)),
	}
	return append(header, handshake...)
}

func ja3FromRawClientHello(raw []byte) (string, string, error) {
	if len(raw) < 11 {
		return "", "", fmt.Errorf("ClientHello record too short: %d bytes", len(raw))
	}
	if raw[0] != 22 || raw[5] != 1 {
		return "", "", fmt.Errorf("record is not a TLS ClientHello")
	}

	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(raw)
	if err != nil {
		return "", "", err
	}

	version := binary.BigEndian.Uint16(raw[9:11])
	ja3 := strings.Join([]string{
		strconv.Itoa(int(version)),
		joinJA3Uint16s(spec.CipherSuites),
		joinJA3Uint16s(ja3ExtensionIDs(spec.Extensions)),
		joinJA3CurveIDs(spec.Extensions),
		joinJA3PointFormats(spec.Extensions),
	}, ",")
	sum := md5.Sum([]byte(ja3))
	return ja3, hex.EncodeToString(sum[:]), nil
}

func joinJA3Uint16s(values []uint16) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		if isJA3GREASE(value) {
			continue
		}
		parts = append(parts, strconv.Itoa(int(value)))
	}
	return strings.Join(parts, "-")
}

func joinJA3CurveIDs(extensions []utls.TLSExtension) string {
	for _, extension := range extensions {
		curves, ok := extension.(*utls.SupportedCurvesExtension)
		if !ok {
			continue
		}

		values := make([]uint16, 0, len(curves.Curves))
		for _, curve := range curves.Curves {
			values = append(values, uint16(curve))
		}
		return joinJA3Uint16s(values)
	}
	return ""
}

func joinJA3PointFormats(extensions []utls.TLSExtension) string {
	for _, extension := range extensions {
		points, ok := extension.(*utls.SupportedPointsExtension)
		if !ok {
			continue
		}

		parts := make([]string, 0, len(points.SupportedPoints))
		for _, point := range points.SupportedPoints {
			parts = append(parts, strconv.Itoa(int(point)))
		}
		return strings.Join(parts, "-")
	}
	return ""
}

func ja3ExtensionIDs(extensions []utls.TLSExtension) []uint16 {
	ids := make([]uint16, 0, len(extensions))
	for _, extension := range extensions {
		id, ok := ja3ExtensionID(extension)
		if ok && !isJA3GREASE(id) {
			ids = append(ids, id)
		}
	}
	return ids
}

func ja3ExtensionID(extension utls.TLSExtension) (uint16, bool) {
	if extension.Len() >= 2 {
		buf := make([]byte, extension.Len())
		n, _ := extension.Read(buf)
		if n >= 2 {
			return binary.BigEndian.Uint16(buf[:2]), true
		}
	}

	switch extension.(type) {
	case *utls.SNIExtension:
		return 0, true
	default:
		return 0, false
	}
}

func isJA3GREASE(value uint16) bool {
	high := byte(value >> 8)
	low := byte(value)
	return value == utls.GREASE_PLACEHOLDER || high == low && high&0x0f == 0x0a
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
