package main

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestStripPort(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "hostname with port", in: "example.com:443", want: "example.com"},
		{name: "hostname without port", in: "example.com", want: "example.com"},
		{name: "ipv4 with port", in: "127.0.0.1:8080", want: "127.0.0.1"},
		{name: "ipv4 without port", in: "127.0.0.1", want: "127.0.0.1"},
		{name: "bracketed ipv6 with port", in: "[2606:4700:4700::1111]:443", want: "2606:4700:4700::1111"},
		{name: "bracketed ipv6 without port", in: "[2606:4700:4700::1111]", want: "2606:4700:4700::1111"},
		{name: "ipv6 without port", in: "2606:4700:4700::1111", want: "2606:4700:4700::1111"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripPort(tt.in); got != tt.want {
				t.Fatalf("stripPort(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestGenerateCertificateMissingSessionKeyReturnsError(t *testing.T) {
	oldConfig := Config
	oldCA := CA
	oldSessionKey := SessionKey
	t.Cleanup(func() {
		Config = oldConfig
		CA = oldCA
		SessionKey = oldSessionKey
	})

	dir := t.TempDir()
	Config.Cert = filepath.Join(dir, "ca.pem")
	Config.Key = filepath.Join(dir, "ca-key.pem")

	if err := generateCA(); err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}
	SessionKey = SessionKeyHelper{}

	if _, err := generateCertificate("example.com:443"); err == nil {
		t.Fatal("generateCertificate() error = nil, want missing session key error")
	}
}

func TestGenerateCertificateMissingCAReturnsError(t *testing.T) {
	oldCA := CA
	oldSessionKey := SessionKey
	t.Cleanup(func() {
		CA = oldCA
		SessionKey = oldSessionKey
	})

	CA = CertificateAuthority{}
	if err := generateSessionKey(); err != nil {
		t.Fatalf("generateSessionKey() error = %v", err)
	}

	if _, err := generateCertificate("example.com:443"); err == nil {
		t.Fatal("generateCertificate() error = nil, want missing CA error")
	}
}

func TestLoadExistingCAMissingFilesReturnsError(t *testing.T) {
	oldConfig := Config
	t.Cleanup(func() {
		Config = oldConfig
	})

	dir := t.TempDir()
	Config.Cert = filepath.Join(dir, "missing-ca.pem")
	Config.Key = filepath.Join(dir, "missing-key.pem")

	if err := loadExistingCA(); err == nil {
		t.Fatal("loadExistingCA() error = nil, want missing file error")
	}
}

func TestGenerateCAAndCertificate(t *testing.T) {
	oldConfig := Config
	oldCA := CA
	oldSessionKey := SessionKey
	t.Cleanup(func() {
		Config = oldConfig
		CA = oldCA
		SessionKey = oldSessionKey
	})

	dir := t.TempDir()
	Config.Cert = filepath.Join(dir, "ca.pem")
	Config.Key = filepath.Join(dir, "ca-key.pem")

	if err := generateCA(); err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}

	if _, err := os.Stat(Config.Cert); err != nil {
		t.Fatalf("expected generated CA cert file: %v", err)
	}
	if _, err := os.Stat(Config.Key); err != nil {
		t.Fatalf("expected generated CA key file: %v", err)
	}
	if CA.x509Cert == nil {
		t.Fatal("expected CA.x509Cert to be set")
	}

	CA = CertificateAuthority{}
	if err := loadExistingCA(); err != nil {
		t.Fatalf("loadExistingCA() error = %v", err)
	}
	if CA.x509Cert == nil {
		t.Fatal("expected loadExistingCA to populate CA.x509Cert")
	}

	if err := generateSessionKey(); err != nil {
		t.Fatalf("generateSessionKey() error = %v", err)
	}
	if SessionKey.privateKey == nil {
		t.Fatal("expected SessionKey.privateKey to be set")
	}
	if len(SessionKey.PEMBlock) == 0 {
		t.Fatal("expected SessionKey.PEMBlock to be set")
	}

	cert, err := generateCertificate("example.com:443")
	if err != nil {
		t.Fatalf("generateCertificate() error = %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected generated certificate chain")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if leaf.Subject.CommonName != "example.com" {
		t.Fatalf("generated certificate CN = %q, want %q", leaf.Subject.CommonName, "example.com")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Fatalf("generated certificate DNSNames = %v, want [example.com]", leaf.DNSNames)
	}
}

func TestGenerateCACreatesParentDirectories(t *testing.T) {
	oldConfig := Config
	oldCA := CA
	t.Cleanup(func() {
		Config = oldConfig
		CA = oldCA
	})

	dir := t.TempDir()
	Config.Cert = filepath.Join(dir, "credentials", "cert.pem")
	Config.Key = filepath.Join(dir, "credentials", "key.pem")

	if err := generateCA(); err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}

	if _, err := os.Stat(Config.Cert); err != nil {
		t.Fatalf("expected generated CA cert file: %v", err)
	}
	if _, err := os.Stat(Config.Key); err != nil {
		t.Fatalf("expected generated CA key file: %v", err)
	}
}

func TestGenerateCAWithRootRelativePaths(t *testing.T) {
	oldConfig := Config
	oldCA := CA
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	dir := t.TempDir()
	t.Cleanup(func() {
		Config = oldConfig
		CA = oldCA
		if err := os.Chdir(oldWd); err != nil {
			t.Fatalf("Chdir(%q) error = %v", oldWd, err)
		}
	})

	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir(%q) error = %v", dir, err)
	}
	Config.Cert = "cert.pem"
	Config.Key = "key.pem"

	if err := generateCA(); err != nil {
		t.Fatalf("generateCA() error = %v", err)
	}

	if _, err := os.Stat("cert.pem"); err != nil {
		t.Fatalf("expected generated root-relative CA cert file: %v", err)
	}
	if _, err := os.Stat("key.pem"); err != nil {
		t.Fatalf("expected generated root-relative CA key file: %v", err)
	}
}
