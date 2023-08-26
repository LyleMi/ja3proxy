package main

type RunningConfig struct {
	Debug      bool
	Addr       string
	Port       string
	TLSVersion string
	TLSClient  string
	Cert       string
	Key        string
}

var (
	Config RunningConfig
)
