package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newRuntimeTestApp(t *testing.T) *App {
	t.Helper()

	config := &RunningConfig{
		Addr:       "127.0.0.1",
		Port:       "0",
		TLSClient:  "Golang",
		TLSVersion: "0",
	}
	ca := &CertificateAuthority{}
	sessionKey := &SessionKeyHelper{}
	fingerprints := &TLSFingerprintStore{}
	var upstreamDialer *UpstreamDialer

	return &App{
		Config:          config,
		CA:              ca,
		SessionKey:      sessionKey,
		TLSFingerprints: fingerprints,
		upstreamDialer:  &upstreamDialer,
	}
}

func TestEnsureCAReturnsErrorWhenOnlyCertExists(t *testing.T) {
	app := newRuntimeTestApp(t)
	dir := t.TempDir()
	app.Config.Cert = filepath.Join(dir, "cert.pem")
	app.Config.Key = filepath.Join(dir, "key.pem")

	if err := os.WriteFile(app.Config.Cert, []byte("cert"), 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	err := app.ensureCA()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "found CA cert") {
		t.Fatalf("error = %q, want CA cert context", err)
	}
}

func TestEnsureCAReturnsErrorWhenOnlyKeyExists(t *testing.T) {
	app := newRuntimeTestApp(t)
	dir := t.TempDir()
	app.Config.Cert = filepath.Join(dir, "cert.pem")
	app.Config.Key = filepath.Join(dir, "key.pem")

	if err := os.WriteFile(app.Config.Key, []byte("key"), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	err := app.ensureCA()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "found CA key") {
		t.Fatalf("error = %q, want CA key context", err)
	}
}

func TestConfigureTLSFingerprintReturnsValidationError(t *testing.T) {
	app := newRuntimeTestApp(t)
	app.Config.TLSClient = "UnsupportedClient"
	app.Config.TLSVersion = "0"

	err := app.configureTLSFingerprint()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed configuring TLS fingerprint") {
		t.Fatalf("error = %q, want fingerprint context", err)
	}
}

func TestConfigureTLSFingerprintReturnsFileError(t *testing.T) {
	app := newRuntimeTestApp(t)
	app.Config.FingerprintConfig = filepath.Join(t.TempDir(), "missing.json")

	err := app.configureTLSFingerprint()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed loading fingerprint config") {
		t.Fatalf("error = %q, want fingerprint file context", err)
	}
}

func TestBuildProxyReturnsUpstreamValidationError(t *testing.T) {
	app := newRuntimeTestApp(t)
	app.Config.Upstream = "http://127.0.0.1:1080"

	proxy, err := app.buildProxy()
	if err == nil {
		t.Fatal("expected error")
	}
	if proxy != nil {
		t.Fatalf("proxy = %#v, want nil", proxy)
	}
	if !strings.Contains(err.Error(), "configure upstream proxy") {
		t.Fatalf("error = %q, want upstream context", err)
	}
}
