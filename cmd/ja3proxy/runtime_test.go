package main

import (
	"flag"
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

	return &App{
		Config:          config,
		CA:              ca,
		SessionKey:      sessionKey,
		TLSFingerprints: fingerprints,
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

func TestParseFlagsAppliesArgs(t *testing.T) {
	app := newRuntimeTestApp(t)

	err := app.parseFlags([]string{
		"-cert", "custom-cert.pem",
		"-key", "custom-key.pem",
		"-addr", "127.0.0.1",
		"-port", "9090",
		"-client", "Chrome",
		"-version", "120",
		"-fingerprint-config", "fingerprints.json",
		"-upstream", "127.0.0.1:1080",
		"-debug",
	})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	if app.Config.Cert != "custom-cert.pem" {
		t.Fatalf("cert = %q, want custom-cert.pem", app.Config.Cert)
	}
	if app.Config.Key != "custom-key.pem" {
		t.Fatalf("key = %q, want custom-key.pem", app.Config.Key)
	}
	if app.Config.Addr != "127.0.0.1" {
		t.Fatalf("addr = %q, want 127.0.0.1", app.Config.Addr)
	}
	if app.Config.Port != "9090" {
		t.Fatalf("port = %q, want 9090", app.Config.Port)
	}
	if app.Config.TLSClient != "Chrome" {
		t.Fatalf("client = %q, want Chrome", app.Config.TLSClient)
	}
	if app.Config.TLSVersion != "120" {
		t.Fatalf("version = %q, want 120", app.Config.TLSVersion)
	}
	if app.Config.FingerprintConfig != "fingerprints.json" {
		t.Fatalf("fingerprint config = %q, want fingerprints.json", app.Config.FingerprintConfig)
	}
	if app.Config.Upstream != "127.0.0.1:1080" {
		t.Fatalf("upstream = %q, want 127.0.0.1:1080", app.Config.Upstream)
	}
	if !app.Config.Debug {
		t.Fatal("debug = false, want true")
	}
	if flag.CommandLine.Lookup("cert") != nil {
		t.Fatal("parseFlags registered cert on global flag.CommandLine")
	}
}

func TestParseFlagsReturnsErrorForInvalidFlag(t *testing.T) {
	app := newRuntimeTestApp(t)

	err := app.parseFlags([]string{"-unknown"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("error = %q, want unknown flag context", err)
	}
	if flag.CommandLine.Lookup("unknown") != nil {
		t.Fatal("parseFlags registered unknown on global flag.CommandLine")
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
