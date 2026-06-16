package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

type TLSFingerprint struct {
	Client  string `json:"client"`
	Version string `json:"version"`
}

var (
	tlsFingerprintMu      sync.RWMutex
	currentTLSFingerprint *TLSFingerprint
)

func configuredTLSFingerprint() TLSFingerprint {
	tlsFingerprintMu.RLock()
	defer tlsFingerprintMu.RUnlock()

	if currentTLSFingerprint != nil {
		return *currentTLSFingerprint
	}

	return TLSFingerprint{
		Client:  Config.TLSClient,
		Version: Config.TLSVersion,
	}
}

func setTLSFingerprint(fingerprint TLSFingerprint) error {
	if fingerprint.Client == "" {
		return fmt.Errorf("fingerprint client is required")
	}
	if fingerprint.Version == "" {
		return fmt.Errorf("fingerprint version is required")
	}
	if err := validateTLSFingerprint(fingerprint); err != nil {
		return err
	}

	tlsFingerprintMu.Lock()
	defer tlsFingerprintMu.Unlock()

	f := fingerprint
	currentTLSFingerprint = &f
	return nil
}

func validateTLSFingerprint(fingerprint TLSFingerprint) error {
	clientHelloID := utls.ClientHelloID{
		Client:  fingerprint.Client,
		Version: fingerprint.Version,
	}
	if clientHelloID.Client == utls.HelloGolang.Client {
		return nil
	}
	if _, err := utls.UTLSIdToSpec(clientHelloID); err != nil {
		return fmt.Errorf("unsupported TLS fingerprint %s %s: %w", fingerprint.Version, fingerprint.Client, err)
	}
	return nil
}

func resetTLSFingerprint() {
	tlsFingerprintMu.Lock()
	defer tlsFingerprintMu.Unlock()

	currentTLSFingerprint = nil
}

func loadTLSFingerprintFile(path string) (TLSFingerprint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TLSFingerprint{}, err
	}

	var fingerprint TLSFingerprint
	if err := json.Unmarshal(data, &fingerprint); err != nil {
		return TLSFingerprint{}, err
	}
	if fingerprint.Client == "" {
		return TLSFingerprint{}, fmt.Errorf("fingerprint client is required")
	}
	if fingerprint.Version == "" {
		return TLSFingerprint{}, fmt.Errorf("fingerprint version is required")
	}
	return fingerprint, nil
}

func applyTLSFingerprintFile(path string) error {
	fingerprint, err := loadTLSFingerprintFile(path)
	if err != nil {
		return err
	}
	if err := setTLSFingerprint(fingerprint); err != nil {
		return err
	}

	log.Printf("loaded TLS fingerprint %s %s from %s", fingerprint.Version, fingerprint.Client, path)
	return nil
}

func watchTLSFingerprintFile(ctx context.Context, path string, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("fingerprint reload interval must be positive")
	}
	if err := applyTLSFingerprintFile(path); err != nil {
		return err
	}

	stat, err := os.Stat(path)
	if err != nil {
		return err
	}
	lastModTime := stat.ModTime()
	lastSize := stat.Size()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stat, err := os.Stat(path)
				if err != nil {
					log.Printf("check TLS fingerprint config: %v", err)
					continue
				}
				if !stat.ModTime().After(lastModTime) && stat.Size() == lastSize {
					continue
				}

				if err := applyTLSFingerprintFile(path); err != nil {
					log.Printf("reload TLS fingerprint config: %v", err)
					continue
				}
				lastModTime = stat.ModTime()
				lastSize = stat.Size()
			}
		}
	}()

	return nil
}
