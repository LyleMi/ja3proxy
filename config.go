package main

import (
	"crypto/tls"
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

var (
	Config       RunningConfig
	LoadedCert   tls.Certificate
	CustomDialer *UpstreamDialer
)
