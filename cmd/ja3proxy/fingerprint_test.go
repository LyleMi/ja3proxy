package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfiguredTLSFingerprintFallsBackToConfig(t *testing.T) {
	config := &RunningConfig{TLSClient: "Chrome", TLSVersion: "106"}
	store := &TLSFingerprintStore{}
	app := &App{Config: config, TLSFingerprints: store}

	got := app.configuredTLSFingerprint()
	if got.Client != "Chrome" || got.Version != "106" {
		t.Fatalf("App.configuredTLSFingerprint() = %+v, want Chrome 106", got)
	}
}

func TestSetTLSFingerprintOverridesConfig(t *testing.T) {
	config := &RunningConfig{TLSClient: "Golang", TLSVersion: "0"}
	store := &TLSFingerprintStore{}
	app := &App{Config: config, TLSFingerprints: store}

	if err := store.SetValidated(TLSFingerprint{Client: "Firefox", Version: "105"}); err != nil {
		t.Fatalf("TLSFingerprintStore.SetValidated() error = %v", err)
	}

	got := app.configuredTLSFingerprint()
	if got.Client != "Firefox" || got.Version != "105" {
		t.Fatalf("App.configuredTLSFingerprint() = %+v, want Firefox 105", got)
	}
}

func TestSetTLSFingerprintValidatesRequiredFields(t *testing.T) {
	store := &TLSFingerprintStore{}

	if err := store.SetValidated(TLSFingerprint{Version: "106"}); err == nil {
		t.Fatal("TLSFingerprintStore.SetValidated() error = nil, want missing client error")
	}
	if err := store.SetValidated(TLSFingerprint{Client: "Chrome"}); err == nil {
		t.Fatal("TLSFingerprintStore.SetValidated() error = nil, want missing version error")
	}
	if err := store.SetValidated(TLSFingerprint{Client: "NoSuchClient", Version: "999"}); err == nil {
		t.Fatal("TLSFingerprintStore.SetValidated() error = nil, want unsupported fingerprint error")
	}
}

func TestTunnelHandlerConfiguredTLSFingerprintUsesInstanceStore(t *testing.T) {
	var store TLSFingerprintStore
	store.Set(TLSFingerprint{Client: "Firefox", Version: "105"})
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

func TestTunnelHandlerConfiguredTLSFingerprintFallsBackToInstanceDefaults(t *testing.T) {
	var store TLSFingerprintStore
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

func TestLoadTLSFingerprintFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fingerprint.json")
	if err := os.WriteFile(path, []byte(`{"client":"Chrome","version":"106"}`), 0o600); err != nil {
		t.Fatalf("write fingerprint file: %v", err)
	}

	got, err := loadTLSFingerprintFile(path)
	if err != nil {
		t.Fatalf("loadTLSFingerprintFile() error = %v", err)
	}
	if got.Client != "Chrome" || got.Version != "106" {
		t.Fatalf("loadTLSFingerprintFile() = %+v, want Chrome 106", got)
	}
}

func TestWatchTLSFingerprintFileReloadsChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fingerprint.json")
	if err := os.WriteFile(path, []byte(`{"client":"Chrome","version":"106"}`), 0o600); err != nil {
		t.Fatalf("write initial fingerprint file: %v", err)
	}

	store := &TLSFingerprintStore{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := store.WatchFile(ctx, path, 10*time.Millisecond); err != nil {
		t.Fatalf("TLSFingerprintStore.WatchFile() error = %v", err)
	}

	got, ok := store.Get()
	if !ok {
		t.Fatal("TLSFingerprintStore.Get() ok = false, want loaded fingerprint")
	}
	if got.Client != "Chrome" || got.Version != "106" {
		t.Fatalf("initial TLSFingerprintStore.Get() = %+v, want Chrome 106", got)
	}

	if err := os.WriteFile(path, []byte(`{"client":"Firefox","version":"105"}`), 0o600); err != nil {
		t.Fatalf("write updated fingerprint file: %v", err)
	}
	if err := os.Chtimes(path, time.Now().Add(time.Second), time.Now().Add(time.Second)); err != nil {
		t.Fatalf("touch updated fingerprint file: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got, ok = store.Get()
		if ok && got.Client == "Firefox" && got.Version == "105" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("TLSFingerprintStore.Get() = %+v, want reloaded Firefox 105", got)
}
