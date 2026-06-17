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

type TLSFingerprintStore struct {
	mu      sync.RWMutex
	current *TLSFingerprint
}

func (s *TLSFingerprintStore) Get() (TLSFingerprint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.current == nil {
		return TLSFingerprint{}, false
	}
	return *s.current, true
}

func (s *TLSFingerprintStore) Set(fingerprint TLSFingerprint) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f := fingerprint
	s.current = &f
}

func (s *TLSFingerprintStore) SetValidated(fingerprint TLSFingerprint) error {
	if fingerprint.Client == "" {
		return fmt.Errorf("fingerprint client is required")
	}
	if fingerprint.Version == "" {
		return fmt.Errorf("fingerprint version is required")
	}
	if err := validateTLSFingerprint(fingerprint); err != nil {
		return err
	}

	s.Set(fingerprint)
	return nil
}

func (s *TLSFingerprintStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.current = nil
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

func (s *TLSFingerprintStore) ApplyFile(path string) error {
	fingerprint, err := loadTLSFingerprintFile(path)
	if err != nil {
		return err
	}
	if err := s.SetValidated(fingerprint); err != nil {
		return err
	}

	log.Printf("loaded TLS fingerprint %s %s from %s", fingerprint.Version, fingerprint.Client, path)
	return nil
}

func (s *TLSFingerprintStore) WatchFile(ctx context.Context, path string, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("fingerprint reload interval must be positive")
	}
	if err := s.ApplyFile(path); err != nil {
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

				if err := s.ApplyFile(path); err != nil {
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
