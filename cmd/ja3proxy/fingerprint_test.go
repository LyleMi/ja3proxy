package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfiguredTLSFingerprintFallsBackToConfig(t *testing.T) {
	oldConfig := Config
	resetTLSFingerprint()
	t.Cleanup(func() {
		Config = oldConfig
		resetTLSFingerprint()
	})

	Config.TLSClient = "Chrome"
	Config.TLSVersion = "106"

	got := configuredTLSFingerprint()
	if got.Client != "Chrome" || got.Version != "106" {
		t.Fatalf("configuredTLSFingerprint() = %+v, want Chrome 106", got)
	}
}

func TestSetTLSFingerprintOverridesConfig(t *testing.T) {
	oldConfig := Config
	resetTLSFingerprint()
	t.Cleanup(func() {
		Config = oldConfig
		resetTLSFingerprint()
	})

	Config.TLSClient = "Golang"
	Config.TLSVersion = "0"

	if err := setTLSFingerprint(TLSFingerprint{Client: "Firefox", Version: "105"}); err != nil {
		t.Fatalf("setTLSFingerprint() error = %v", err)
	}

	got := configuredTLSFingerprint()
	if got.Client != "Firefox" || got.Version != "105" {
		t.Fatalf("configuredTLSFingerprint() = %+v, want Firefox 105", got)
	}
}

func TestSetTLSFingerprintValidatesRequiredFields(t *testing.T) {
	resetTLSFingerprint()
	t.Cleanup(resetTLSFingerprint)

	if err := setTLSFingerprint(TLSFingerprint{Version: "106"}); err == nil {
		t.Fatal("setTLSFingerprint() error = nil, want missing client error")
	}
	if err := setTLSFingerprint(TLSFingerprint{Client: "Chrome"}); err == nil {
		t.Fatal("setTLSFingerprint() error = nil, want missing version error")
	}
	if err := setTLSFingerprint(TLSFingerprint{Client: "NoSuchClient", Version: "999"}); err == nil {
		t.Fatal("setTLSFingerprint() error = nil, want unsupported fingerprint error")
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
	resetTLSFingerprint()
	t.Cleanup(resetTLSFingerprint)

	path := filepath.Join(t.TempDir(), "fingerprint.json")
	if err := os.WriteFile(path, []byte(`{"client":"Chrome","version":"106"}`), 0o600); err != nil {
		t.Fatalf("write initial fingerprint file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := watchTLSFingerprintFile(ctx, path, 10*time.Millisecond); err != nil {
		t.Fatalf("watchTLSFingerprintFile() error = %v", err)
	}

	got := configuredTLSFingerprint()
	if got.Client != "Chrome" || got.Version != "106" {
		t.Fatalf("initial configuredTLSFingerprint() = %+v, want Chrome 106", got)
	}

	if err := os.WriteFile(path, []byte(`{"client":"Firefox","version":"105"}`), 0o600); err != nil {
		t.Fatalf("write updated fingerprint file: %v", err)
	}
	if err := os.Chtimes(path, time.Now().Add(time.Second), time.Now().Add(time.Second)); err != nil {
		t.Fatalf("touch updated fingerprint file: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got = configuredTLSFingerprint()
		if got.Client == "Firefox" && got.Version == "105" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("configuredTLSFingerprint() = %+v, want reloaded Firefox 105", got)
}
