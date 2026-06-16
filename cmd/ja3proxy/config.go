package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
)

type RunningConfig struct {
	Debug      bool
	Addr       string
	Port       string
	TLSVersion string
	TLSClient  string
	Cert       string
	Key        string
	Upstream   string
}

type CertificateAuthority struct {
	tlsCert  tls.Certificate
	x509Cert *x509.Certificate
}

type SessionKeyHelper struct {
	privateKey *ecdsa.PrivateKey
	PEMBlock   []byte
}

var (
	Config       RunningConfig
	CustomDialer *UpstreamDialer
	CA           CertificateAuthority
	SessionKey   SessionKeyHelper
)
