package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	cflog "github.com/cloudflare/cfssl/log"
)

func init() {
	cflog.Level = cflog.LevelWarning
}

func main() {
	flag.StringVar(&Config.Cert, "cert", "credentials/cert.pem", "proxy CA cert")
	flag.StringVar(&Config.Key, "key", "credentials/key.pem", "proxy CA key")
	flag.StringVar(&Config.Addr, "addr", "", "proxy listen host")
	flag.StringVar(&Config.Port, "port", "8080", "proxy listen port")
	flag.StringVar(&Config.TLSClient, "client", "Golang", "utls client")
	flag.StringVar(&Config.TLSVersion, "version", "0", "utls client version")
	flag.StringVar(&Config.FingerprintConfig, "fingerprint-config", "", "JSON file to hot-reload utls client/version")
	flag.StringVar(&Config.Upstream, "upstream", "", "upstream proxy, e.g. 127.0.0.1:1080, socks5 only")
	flag.BoolVar(&Config.Debug, "debug", false, "enable debug")
	flag.Parse()

	if Config.Debug {
		cflog.Level = cflog.LevelDebug
	}

	if !fileExists(Config.Cert) || !fileExists(Config.Key) {
		if fileExists(Config.Cert) {
			log.Println("found CA cert, but no corresponding key")
			os.Exit(-1)
		} else if fileExists(Config.Key) {
			log.Println("found CA key, but no corresponding cert")
			os.Exit(-1)
		}

		log.Println("CA cert and key do not exist, generating")
		err := generateCA()
		if err != nil {
			log.Fatal("Failed generating CA", err)
		}
	}

	loadExistingCA()
	generateSessionKey()

	if Config.FingerprintConfig != "" {
		if err := watchTLSFingerprintFile(context.Background(), Config.FingerprintConfig, 2*time.Second); err != nil {
			log.Fatal("Failed loading fingerprint config", err)
		}
	} else if err := setTLSFingerprint(TLSFingerprint{
		Client:  Config.TLSClient,
		Version: Config.TLSVersion,
	}); err != nil {
		log.Fatal("Failed configuring TLS fingerprint", err)
	}

	var err error
	CustomDialer, err = NewUpstreamDialer(Config.Upstream, time.Second*10)

	if err != nil {
		log.Fatal(err)
	}

	proxy := NewProxy(CustomDialer.Dial, tunnelConnect, CustomDialer.Transport)
	listener, err := net.Listen("tcp", Config.Addr+":"+Config.Port)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Handler: proxy,
	}

	fmt.Printf(
		"HTTP/SOCKS5 Proxy Server listen at %s:%s, with tls fingerprint %s %s\n",
		Config.Addr, Config.Port, configuredTLSFingerprint().Version, configuredTLSFingerprint().Client,
	)
	err = server.Serve(newMixedProxyListener(listener, proxy))
	if err != nil {
		log.Fatal(err)
		os.Exit(-1)
	}
}
