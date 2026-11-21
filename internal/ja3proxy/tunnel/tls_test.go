package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/certstore"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/upstreamtls"
	utls "github.com/refraction-networking/utls"
)

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

func TestGenerateCertificateNilGuardReturnsErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler *TunnelHandler
		want    string
	}{
		{
			name:    "nil handler",
			handler: nil,
			want:    "CA certificate has not been loaded",
		},
		{
			name:    "nil CA",
			handler: &TunnelHandler{},
			want:    "CA certificate has not been loaded",
		},
		{
			name:    "nil session key",
			handler: &TunnelHandler{CA: &certstore.CertificateAuthority{}},
			want:    "session key has not been generated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.handler.generateCertificate("example.com:443"); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("TunnelHandler.generateCertificate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestConfiguredTLSFingerprintUsesInstanceStore(t *testing.T) {
	var store fingerprint.TLSFingerprintStore
	store.Set(fingerprint.TLSFingerprint{Client: "Firefox", Version: "105"})
	handler := &TunnelHandler{
		TLSFingerprints:   &store,
		DefaultTLSClient:  "Golang",
		DefaultTLSVersion: "0",
	}

	got := handler.configuredTLSFingerprint()
	if got.Client != "Firefox" || got.Version != "105" {
		t.Fatalf("handler.configuredTLSFingerprint() = %+v, want Firefox 105", got)
	}
}

func TestConfiguredTLSFingerprintFallsBackToInstanceDefaults(t *testing.T) {
	var store fingerprint.TLSFingerprintStore
	handler := &TunnelHandler{
		TLSFingerprints:   &store,
		DefaultTLSClient:  "Golang",
		DefaultTLSVersion: "0",
	}

	got := handler.configuredTLSFingerprint()
	if got.Client != "Golang" || got.Version != "0" {
		t.Fatalf("handler.configuredTLSFingerprint() = %+v, want Golang 0", got)
	}
}

func TestConfiguredUpstreamTLSProfileFallsBackToCurrentFingerprint(t *testing.T) {
	store := &fingerprint.TLSFingerprintStore{}
	store.Set(fingerprint.TLSFingerprint{Client: "Firefox", Version: "105"})
	handler := &TunnelHandler{
		TLSFingerprints:   store,
		DefaultTLSClient:  "Chrome",
		DefaultTLSVersion: "120",
	}

	got := handler.configuredUpstreamTLSProfile("example.com")
	if got.Protocol != upstreamtls.ProtocolUTLS || got.Client != "Firefox" || got.Version != "105" {
		t.Fatalf("configuredUpstreamTLSProfile() = %+v, want Firefox 105", got)
	}
}

func TestConfiguredUpstreamTLSProfileUsesRouteStore(t *testing.T) {
	profiles := &upstreamtls.UpstreamTLSProfileStore{}
	profiles.Set(upstreamtls.UpstreamTLSConfig{
		Default: upstreamtls.UpstreamTLSProfile{Protocol: "utls", Client: "Chrome", Version: "120"},
		Routes: []upstreamtls.UpstreamTLSRoute{
			{
				Host:               "*.example.com",
				UpstreamTLSProfile: upstreamtls.UpstreamTLSProfile{Protocol: "utls", Client: "Firefox", Version: "105"},
			},
		},
	})
	handler := &TunnelHandler{
		UpstreamTLSProfiles: profiles,
		DefaultTLSClient:    "Golang",
		DefaultTLSVersion:   "0",
	}

	got := handler.configuredUpstreamTLSProfile("api.example.com")
	if got.Protocol != upstreamtls.ProtocolUTLS || got.Client != "Firefox" || got.Version != "105" {
		t.Fatalf("configuredUpstreamTLSProfile() = %+v, want Firefox 105 route", got)
	}
}

func TestLimitSpecALPN(t *testing.T) {
	spec := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1", "h3"}},
			&utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2", "h3"}},
			&utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2", "h3"}},
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

func TestLimitSpecALPNKeepsMatchingApplicationSettings(t *testing.T) {
	sni := &utls.SNIExtension{}
	alpn := &utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1", "h3"}}
	oldALPS := &utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2", "h3"}}
	newALPS := &utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2", "h3"}}
	spec := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{sni, alpn, oldALPS, newALPS},
	}

	limitSpecALPN(spec, []string{"h2", "http/1.1"})

	if !reflect.DeepEqual(spec.Extensions, []utls.TLSExtension{sni, alpn, oldALPS, newALPS}) {
		t.Fatalf("extensions changed order or were removed: %v", spec.Extensions)
	}
	if !reflect.DeepEqual(alpn.AlpnProtocols, []string{"h2", "http/1.1"}) {
		t.Fatalf("ALPN protocols = %v, want [h2 http/1.1]", alpn.AlpnProtocols)
	}
	if !reflect.DeepEqual(oldALPS.SupportedProtocols, []string{"h2"}) {
		t.Fatalf("old ALPS protocols = %v, want [h2]", oldALPS.SupportedProtocols)
	}
	if !reflect.DeepEqual(newALPS.SupportedProtocols, []string{"h2"}) {
		t.Fatalf("new ALPS protocols = %v, want [h2]", newALPS.SupportedProtocols)
	}
}

func TestCustomTLSWrapHandshakeNegotiatesALPNAndSNI(t *testing.T) {
	const serverName = "upstream.test"
	nextProtos := []string{"h2", "http/1.1"}
	listener, serverResults := newLocalTLSServer(t, []string{"h2", "http/1.1"})
	handler := &TunnelHandler{
		DefaultTLSClient:  utls.HelloGolang.Client,
		DefaultTLSVersion: utls.HelloGolang.Version,
	}

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial local TLS server: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	tlsConn, err := handler.customTLSWrap(conn, serverName, nextProtos)
	if err != nil {
		conn.Close()
		t.Fatalf("TunnelHandler.customTLSWrap() error = %v", err)
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
	const serverName = "upstream.test"
	nextProtos := []string{"http/1.1"}
	listener, serverResults := newLocalTLSServer(t, []string{"h2", "http/1.1"})
	handler := &TunnelHandler{
		DefaultTLSClient:  utls.HelloFirefox_Auto.Client,
		DefaultTLSVersion: utls.HelloFirefox_Auto.Version,
	}

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial local TLS server: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	tlsConn, err := handler.customTLSWrap(conn, serverName, nextProtos)
	if err != nil {
		conn.Close()
		t.Fatalf("TunnelHandler.customTLSWrap() error = %v", err)
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
	listener := newBadUpstreamServer(t, func(conn net.Conn) {
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	})
	handler := &TunnelHandler{
		DefaultTLSClient:  utls.HelloGolang.Client,
		DefaultTLSVersion: utls.HelloGolang.Version,
	}

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial bad upstream: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	tlsConn, err := handler.customTLSWrap(conn, "upstream.test", []string{"http/1.1"})
	if err == nil {
		tlsConn.Close()
		t.Fatal("TunnelHandler.customTLSWrap() error = nil, want handshake error")
	}
	conn.Close()
}

func TestConnectMITMHandshakeAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	ca := certstore.CertificateAuthority{}
	if err := ca.Generate(certPath, keyPath); err != nil {
		t.Fatalf("certstore.CertificateAuthority.Generate() error = %v", err)
	}
	session := certstore.SessionKeyHelper{}
	if err := session.Generate(); err != nil {
		t.Fatalf("certstore.SessionKeyHelper.Generate() error = %v", err)
	}
	handler := &TunnelHandler{
		CA:                &ca,
		SessionKey:        &session,
		DefaultTLSClient:  utls.HelloGolang.Client,
		DefaultTLSVersion: utls.HelloGolang.Version,
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
		handler.Connect(serverName, destConn, clientConn)
		close(connectDone)
	}()

	roots := x509.NewCertPool()
	roots.AddCert(ca.X509Certificate())
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
	if err := leaf.CheckSignatureFrom(ca.X509Certificate()); err != nil {
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
