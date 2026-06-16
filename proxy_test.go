package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func replaceDefaultTransport(t *testing.T, rt http.RoundTripper) {
	t.Helper()

	original := http.DefaultTransport
	http.DefaultTransport = rt
	t.Cleanup(func() {
		http.DefaultTransport = original
	})
}

func TestMatchingProtocols(t *testing.T) {
	tests := []struct {
		name      string
		supported []string
		allowed   []string
		want      []string
	}{
		{
			name:      "keeps supported order",
			supported: []string{"h2", "http/1.1", "h3"},
			allowed:   []string{"http/1.1", "h2"},
			want:      []string{"h2", "http/1.1"},
		},
		{
			name:      "no overlap",
			supported: []string{"h3"},
			allowed:   []string{"h2", "http/1.1"},
			want:      []string{},
		},
		{
			name:      "empty allowed",
			supported: []string{"h2"},
			allowed:   nil,
			want:      []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchingProtocols(tt.supported, tt.allowed); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("matchingProtocols() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "exists.txt")
	if err := os.WriteFile(existing, []byte("ok"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	if !fileExists(existing) {
		t.Fatalf("fileExists(%q) = false, want true", existing)
	}

	missing := filepath.Join(dir, "missing.txt")
	if fileExists(missing) {
		t.Fatalf("fileExists(%q) = true, want false", missing)
	}
}

func TestUpstreamALPN(t *testing.T) {
	if got := upstreamALPN(nil); !reflect.DeepEqual(got, []string{"http/1.1"}) {
		t.Fatalf("upstreamALPN(nil) = %v, want [http/1.1]", got)
	}

	input := []string{"h2", "http/1.1"}
	if got := upstreamALPN(input); !reflect.DeepEqual(got, input) {
		t.Fatalf("upstreamALPN(%v) = %v, want %v", input, got, input)
	}
}

func TestClientALPN(t *testing.T) {
	if got := clientALPN(""); !reflect.DeepEqual(got, []string{"http/1.1"}) {
		t.Fatalf("clientALPN(\"\") = %v, want [http/1.1]", got)
	}

	if got := clientALPN("h2"); !reflect.DeepEqual(got, []string{"h2"}) {
		t.Fatalf("clientALPN(\"h2\") = %v, want [h2]", got)
	}
}

func TestLimitSpecALPN(t *testing.T) {
	spec := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1", "h3"}},
			&utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2", "h3"}},
		},
	}

	limitSpecALPN(spec, []string{"http/1.1"})

	if len(spec.Extensions) != 2 {
		t.Fatalf("extension count after filtering = %d, want 2", len(spec.Extensions))
	}

	alpn, ok := spec.Extensions[1].(*utls.ALPNExtension)
	if !ok {
		t.Fatalf("extension[1] = %T, want *utls.ALPNExtension", spec.Extensions[1])
	}
	if !reflect.DeepEqual(alpn.AlpnProtocols, []string{"http/1.1"}) {
		t.Fatalf("ALPN protocols = %v, want [http/1.1]", alpn.AlpnProtocols)
	}
}

func TestCustomTLSWrapHandshakeNegotiatesALPNAndSNI(t *testing.T) {
	oldConfig := Config
	Config.TLSClient = utls.HelloGolang.Client
	Config.TLSVersion = utls.HelloGolang.Version
	t.Cleanup(func() {
		Config = oldConfig
	})

	const serverName = "upstream.test"
	nextProtos := []string{"h2", "http/1.1"}
	listener, serverResults := newLocalTLSServer(t, []string{"h2", "http/1.1"})

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial local TLS server: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	tlsConn, err := customTLSWrap(conn, serverName, nextProtos)
	if err != nil {
		conn.Close()
		t.Fatalf("customTLSWrap() error = %v", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		t.Fatalf("client negotiated protocol = %q, want h2", state.NegotiatedProtocol)
	}

	result := receiveTLSServerResult(t, serverResults)
	if result.err != nil {
		t.Fatalf("server handshake error = %v", result.err)
	}
	if result.serverName != serverName {
		t.Fatalf("server saw SNI = %q, want %q", result.serverName, serverName)
	}
	if result.negotiatedProtocol != "h2" {
		t.Fatalf("server negotiated protocol = %q, want h2", result.negotiatedProtocol)
	}
	if !reflect.DeepEqual(result.supportedProtos, nextProtos) {
		t.Fatalf("server saw client ALPN = %v, want %v", result.supportedProtos, nextProtos)
	}
}

func TestCustomTLSWrapWithUTLSPresetLimitsALPN(t *testing.T) {
	oldConfig := Config
	Config.TLSClient = utls.HelloFirefox_Auto.Client
	Config.TLSVersion = utls.HelloFirefox_Auto.Version
	t.Cleanup(func() {
		Config = oldConfig
	})

	const serverName = "upstream.test"
	nextProtos := []string{"http/1.1"}
	listener, serverResults := newLocalTLSServer(t, []string{"h2", "http/1.1"})

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial local TLS server: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	tlsConn, err := customTLSWrap(conn, serverName, nextProtos)
	if err != nil {
		conn.Close()
		t.Fatalf("customTLSWrap() error = %v", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("client negotiated protocol = %q, want http/1.1", state.NegotiatedProtocol)
	}

	result := receiveTLSServerResult(t, serverResults)
	if result.err != nil {
		t.Fatalf("server handshake error = %v", result.err)
	}
	if result.serverName != serverName {
		t.Fatalf("server saw SNI = %q, want %q", result.serverName, serverName)
	}
	if result.negotiatedProtocol != "http/1.1" {
		t.Fatalf("server negotiated protocol = %q, want http/1.1", result.negotiatedProtocol)
	}
	if !reflect.DeepEqual(result.supportedProtos, nextProtos) {
		t.Fatalf("server saw client ALPN = %v, want %v", result.supportedProtos, nextProtos)
	}
}

func TestCustomTLSWrapReturnsHandshakeError(t *testing.T) {
	oldConfig := Config
	Config.TLSClient = utls.HelloGolang.Client
	Config.TLSVersion = utls.HelloGolang.Version
	t.Cleanup(func() {
		Config = oldConfig
	})

	listener := newBadUpstreamServer(t, func(conn net.Conn) {
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	})

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial bad upstream: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	tlsConn, err := customTLSWrap(conn, "upstream.test", []string{"http/1.1"})
	if err == nil {
		tlsConn.Close()
		t.Fatal("customTLSWrap() error = nil, want handshake error")
	}
	conn.Close()
}

func TestConnectMITMHandshakeAndRoundTrip(t *testing.T) {
	oldConfig := Config
	oldCA := CA
	oldSessionKey := SessionKey
	t.Cleanup(func() {
		Config = oldConfig
		CA = oldCA
		SessionKey = oldSessionKey
	})

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

	const serverName = "target.test"
	deadline := time.Now().Add(5 * time.Second)
	destConn, upstreamPeer := net.Pipe()
	clientConn, clientPeer := net.Pipe()
	for _, conn := range []net.Conn{destConn, upstreamPeer, clientConn, clientPeer} {
		defer conn.Close()
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
	}

	upstreamResult := make(chan connectUpstreamResult, 1)
	upstreamCert := localTLSCertificate(t)
	go serveConnectUpstream(upstreamPeer, upstreamCert, upstreamResult)

	connectDone := make(chan struct{})
	go func() {
		connect(serverName, destConn, clientConn)
		close(connectDone)
	}()

	roots := x509.NewCertPool()
	roots.AddCert(CA.x509Cert)
	clientTLSConn := tls.Client(clientPeer, &tls.Config{
		ServerName: serverName,
		RootCAs:    roots,
		NextProtos: []string{"h2", "http/1.1"},
	})
	defer clientTLSConn.Close()
	if err := clientTLSConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set client TLS deadline: %v", err)
	}

	if err := clientTLSConn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake error = %v", err)
	}
	clientState := clientTLSConn.ConnectionState()
	if clientState.NegotiatedProtocol != "h2" {
		t.Fatalf("client negotiated protocol = %q, want h2", clientState.NegotiatedProtocol)
	}
	if len(clientState.PeerCertificates) == 0 {
		t.Fatal("client saw no peer certificate")
	}
	leaf := clientState.PeerCertificates[0]
	if leaf.Subject.CommonName != serverName {
		t.Fatalf("MITM certificate CN = %q, want %q", leaf.Subject.CommonName, serverName)
	}
	if err := leaf.CheckSignatureFrom(CA.x509Cert); err != nil {
		t.Fatalf("MITM certificate was not signed by test CA: %v", err)
	}

	request := []byte("ping through tunnel")
	if _, err := clientTLSConn.Write(request); err != nil {
		t.Fatalf("client write through tunnel: %v", err)
	}

	response := []byte("pong from upstream")
	got := make([]byte, len(response))
	if _, err := io.ReadFull(clientTLSConn, got); err != nil {
		t.Fatalf("client read upstream response: %v", err)
	}
	if string(got) != string(response) {
		t.Fatalf("client got response = %q, want %q", got, response)
	}

	result := receiveConnectUpstreamResult(t, upstreamResult)
	if result.err != nil {
		t.Fatalf("upstream TLS server error = %v", result.err)
	}
	if result.serverName != serverName {
		t.Fatalf("upstream saw SNI = %q, want %q", result.serverName, serverName)
	}
	if !reflect.DeepEqual(result.supportedProtos, []string{"h2", "http/1.1"}) {
		t.Fatalf("upstream saw client ALPN = %v, want [h2 http/1.1]", result.supportedProtos)
	}
	if result.negotiatedProtocol != "h2" {
		t.Fatalf("upstream negotiated protocol = %q, want h2", result.negotiatedProtocol)
	}
	if string(result.request) != string(request) {
		t.Fatalf("upstream got request = %q, want %q", result.request, request)
	}

	clientTLSConn.Close()
	select {
	case <-connectDone:
	case <-time.After(2 * time.Second):
		t.Fatal("connect did not return after client close")
	}
}

type tlsServerResult struct {
	serverName         string
	supportedProtos    []string
	negotiatedProtocol string
	err                error
}

type connectUpstreamResult struct {
	serverName         string
	supportedProtos    []string
	negotiatedProtocol string
	request            []byte
	err                error
}

func serveConnectUpstream(conn net.Conn, cert tls.Certificate, results chan<- connectUpstreamResult) {
	helloInfo := make(chan struct {
		serverName      string
		supportedProtos []string
	}, 1)
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			helloInfo <- struct {
				serverName      string
				supportedProtos []string
			}{
				serverName:      hello.ServerName,
				supportedProtos: append([]string(nil), hello.SupportedProtos...),
			}
			return nil, nil
		},
	})
	defer tlsConn.Close()
	if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		results <- connectUpstreamResult{err: err}
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		results <- connectUpstreamResult{err: err}
		return
	}

	info := <-helloInfo
	request := make([]byte, len("ping through tunnel"))
	if _, err := io.ReadFull(tlsConn, request); err != nil {
		results <- connectUpstreamResult{err: err}
		return
	}
	if _, err := tlsConn.Write([]byte("pong from upstream")); err != nil {
		results <- connectUpstreamResult{err: err}
		return
	}

	results <- connectUpstreamResult{
		serverName:         info.serverName,
		supportedProtos:    info.supportedProtos,
		negotiatedProtocol: tlsConn.ConnectionState().NegotiatedProtocol,
		request:            request,
	}
}

func receiveConnectUpstreamResult(t *testing.T, results <-chan connectUpstreamResult) connectUpstreamResult {
	t.Helper()

	select {
	case result := <-results:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for connect upstream server")
	}
	return connectUpstreamResult{}
}

func newLocalTLSServer(t *testing.T, nextProtos []string) (net.Listener, <-chan tlsServerResult) {
	t.Helper()

	cert := localTLSCertificate(t)
	results := make(chan tlsServerResult, 1)
	helloInfo := make(chan struct {
		serverName      string
		supportedProtos []string
	}, 1)

	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on local TCP address: %v", err)
	}
	t.Cleanup(func() {
		baseListener.Close()
	})

	if tcpListener, ok := baseListener.(*net.TCPListener); ok {
		if err := tcpListener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set listener deadline: %v", err)
		}
	}

	tlsListener := tls.NewListener(baseListener, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   nextProtos,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			helloInfo <- struct {
				serverName      string
				supportedProtos []string
			}{
				serverName:      hello.ServerName,
				supportedProtos: append([]string(nil), hello.SupportedProtos...),
			}
			return nil, nil
		},
	})

	go func() {
		conn, err := tlsListener.Accept()
		if err != nil {
			results <- tlsServerResult{err: err}
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			results <- tlsServerResult{err: err}
			return
		}

		tlsConn := conn.(*tls.Conn)
		err = tlsConn.Handshake()
		result := tlsServerResult{err: err}
		if err == nil {
			info := <-helloInfo
			result.serverName = info.serverName
			result.supportedProtos = info.supportedProtos
			result.negotiatedProtocol = tlsConn.ConnectionState().NegotiatedProtocol
		}
		results <- result
	}()

	return tlsListener, results
}

func receiveTLSServerResult(t *testing.T, results <-chan tlsServerResult) tlsServerResult {
	t.Helper()

	select {
	case result := <-results:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for local TLS server")
	}
	return tlsServerResult{}
}

func newBadUpstreamServer(t *testing.T, handle func(net.Conn)) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on local TCP address: %v", err)
	}
	t.Cleanup(func() {
		listener.Close()
	})

	if tcpListener, ok := listener.(*net.TCPListener); ok {
		if err := tcpListener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set listener deadline: %v", err)
		}
	}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		handle(conn)
	}()

	return listener
}

func localTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test TLS key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"upstream.test"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test TLS certificate: %v", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parse test TLS certificate: %v", err)
	}
	return cert
}

func TestCopyHeader(t *testing.T) {
	src := http.Header{}
	src.Add("Set-Cookie", "a=1")
	src.Add("Set-Cookie", "b=2")
	src.Set("Content-Type", "text/plain")

	dst := http.Header{}
	copyHeader(dst, src)

	if got := dst.Values("Set-Cookie"); !reflect.DeepEqual(got, []string{"a=1", "b=2"}) {
		t.Fatalf("copied Set-Cookie values = %v, want [a=1 b=2]", got)
	}
	if got := dst.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("copied Content-Type = %q, want text/plain", got)
	}
}

func TestJunctionForwardsBothDirections(t *testing.T) {
	destConn, upstreamPeer := net.Pipe()
	clientConn, clientPeer := net.Pipe()
	conns := []net.Conn{destConn, upstreamPeer, clientConn, clientPeer}
	for _, conn := range conns {
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
	}

	done := make(chan struct{})
	go func() {
		junction(destConn, clientConn)
		close(done)
	}()

	assertForward := func(name string, src net.Conn, dst net.Conn, payload []byte) {
		t.Helper()

		writeErr := make(chan error, 1)
		go func() {
			_, err := src.Write(payload)
			writeErr <- err
		}()

		got := make([]byte, len(payload))
		if _, err := io.ReadFull(dst, got); err != nil {
			t.Fatalf("%s read: %v", name, err)
		}
		if string(got) != string(payload) {
			t.Fatalf("%s payload = %q, want %q", name, got, payload)
		}

		select {
		case err := <-writeErr:
			if err != nil {
				t.Fatalf("%s write: %v", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s write timed out", name)
		}
	}

	assertForward("client to upstream", clientPeer, upstreamPeer, []byte("client ping"))
	assertForward("upstream to client", upstreamPeer, clientPeer, []byte("upstream pong"))

	clientPeer.Close()
	upstreamPeer.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("junction did not return after peer connections closed")
	}
}

func TestHandleTunnelingDialErrorReturnsServiceUnavailable(t *testing.T) {
	replaceTunnelDial(t, func(network, addr string) (net.Conn, error) {
		if network != "tcp" {
			t.Fatalf("network = %q, want tcp", network)
		}
		if addr != "example.com:443" {
			t.Fatalf("addr = %q, want example.com:443", addr)
		}
		return nil, errors.New("dial failed")
	})

	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	rec := &hijackResponseRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             clientConn,
	}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"

	handleTunneling(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !strings.Contains(string(body), "dial failed") {
		t.Fatalf("body = %q, want dial error", string(body))
	}
	if rec.hijacked {
		t.Fatal("Hijack was called after dial failure")
	}
}

func TestHandleTunnelingWithoutHijackerReturnsInternalServerError(t *testing.T) {
	replaceTunnelDial(t, func(network, addr string) (net.Conn, error) {
		t.Fatal("tunnelDial should not be called without Hijacker support")
		return nil, nil
	})

	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"
	rec := httptest.NewRecorder()

	handleTunneling(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !strings.Contains(string(body), "Hijacking not supported") {
		t.Fatalf("body = %q, want hijacking error", string(body))
	}
}

func TestHandleTunnelingSuccessDialsHijacksAndConnects(t *testing.T) {
	destConn, destPeer := net.Pipe()
	clientConn, clientPeer := net.Pipe()
	defer destConn.Close()
	defer destPeer.Close()
	defer clientConn.Close()
	defer clientPeer.Close()

	var dialNetwork, dialAddr string
	replaceTunnelDial(t, func(network, addr string) (net.Conn, error) {
		dialNetwork = network
		dialAddr = addr
		return destConn, nil
	})

	connectCalls := make(chan tunnelConnectCall, 1)
	replaceTunnelConnect(t, func(sni string, destConn net.Conn, clientConn net.Conn) {
		connectCalls <- tunnelConnectCall{
			sni:        sni,
			destConn:   destConn,
			clientConn: clientConn,
		}
	})

	rec := &hijackResponseRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             clientConn,
	}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"

	handleTunneling(rec, req)

	if dialNetwork != "tcp" {
		t.Fatalf("dial network = %q, want tcp", dialNetwork)
	}
	if dialAddr != "example.com:443" {
		t.Fatalf("dial addr = %q, want example.com:443", dialAddr)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	if !reflect.DeepEqual(rec.events, []string{"writeHeader", "hijack"}) {
		t.Fatalf("events = %v, want [writeHeader hijack]", rec.events)
	}

	var call tunnelConnectCall
	select {
	case call = <-connectCalls:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for tunnelConnect")
	}

	if call.sni != "example.com" {
		t.Fatalf("connect sni = %q, want example.com", call.sni)
	}
	if call.destConn != destConn {
		t.Fatalf("connect destConn = %p, want %p", call.destConn, destConn)
	}
	if call.clientConn != clientConn {
		t.Fatalf("connect clientConn = %p, want %p", call.clientConn, clientConn)
	}
}

type tunnelConnectCall struct {
	sni        string
	destConn   net.Conn
	clientConn net.Conn
}

type hijackResponseRecorder struct {
	*httptest.ResponseRecorder
	conn     net.Conn
	hijacked bool
	events   []string
}

func (r *hijackResponseRecorder) WriteHeader(code int) {
	r.events = append(r.events, "writeHeader")
	r.ResponseRecorder.WriteHeader(code)
}

func (r *hijackResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r.hijacked = true
	r.events = append(r.events, "hijack")
	rw := bufio.NewReadWriter(bufio.NewReader(r.conn), bufio.NewWriter(r.conn))
	return r.conn, rw, nil
}

func replaceTunnelDial(t *testing.T, dial func(network, addr string) (net.Conn, error)) {
	t.Helper()

	original := tunnelDial
	tunnelDial = dial
	t.Cleanup(func() {
		tunnelDial = original
	})
}

func replaceTunnelConnect(t *testing.T, connect func(sni string, destConn net.Conn, clientConn net.Conn)) {
	t.Helper()

	original := tunnelConnect
	tunnelConnect = connect
	t.Cleanup(func() {
		tunnelConnect = original
	})
}

func TestHandleHTTPWritesUpstreamResponse(t *testing.T) {
	var upstreamReq *http.Request
	replaceDefaultTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamReq = req
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Header: http.Header{
				"Content-Type": {"text/plain"},
				"Set-Cookie":   {"a=1", "b=2"},
				"X-Test":       {"ok"},
			},
			Body: io.NopCloser(strings.NewReader("proxied body")),
		}, nil
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/resource", nil)
	req.RequestURI = "http://example.com/resource"
	rec := httptest.NewRecorder()

	handleHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("Content-Type = %q, want text/plain", got)
	}
	if got := resp.Header.Values("Set-Cookie"); !reflect.DeepEqual(got, []string{"a=1", "b=2"}) {
		t.Fatalf("Set-Cookie values = %v, want [a=1 b=2]", got)
	}
	if got := resp.Header.Get("X-Test"); got != "ok" {
		t.Fatalf("X-Test = %q, want ok", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if got := string(body); got != "proxied body" {
		t.Fatalf("body = %q, want proxied body", got)
	}
	if upstreamReq == nil {
		t.Fatal("RoundTrip was not called")
	}
	if upstreamReq.RequestURI != "" {
		t.Fatalf("upstream RequestURI = %q, want empty", upstreamReq.RequestURI)
	}
}

func TestHandleHTTPRoundTripErrorReturnsServiceUnavailable(t *testing.T) {
	replaceDefaultTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("upstream unavailable")
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/resource", nil)
	rec := httptest.NewRecorder()

	handleHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !strings.Contains(string(body), "upstream unavailable") {
		t.Fatalf("body = %q, want upstream error", string(body))
	}
}
