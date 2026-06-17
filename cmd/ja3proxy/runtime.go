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

type App struct {
	Config          *RunningConfig
	CA              *CertificateAuthority
	SessionKey      *SessionKeyHelper
	TLSFingerprints *TLSFingerprintStore

	upstreamDialer **UpstreamDialer
}

func newDefaultApp() *App {
	return &App{
		Config:          &Config,
		CA:              &CA,
		SessionKey:      &SessionKey,
		TLSFingerprints: &defaultTLSFingerprintStore,
		upstreamDialer:  &CustomDialer,
	}
}

func (app *App) run() {
	app.parseFlags()
	app.configureLogging()
	app.ensureCA()
	if err := app.loadExistingCA(); err != nil {
		log.Fatal("Failed loading CA: ", err)
	}
	if err := app.generateSessionKey(); err != nil {
		log.Fatal("Failed generating session key: ", err)
	}
	app.configureTLSFingerprint()

	proxy := app.buildProxy()
	app.serve(proxy)
}

func (app *App) parseFlags() {
	flag.StringVar(&app.Config.Cert, "cert", "credentials/cert.pem", "proxy CA cert")
	flag.StringVar(&app.Config.Key, "key", "credentials/key.pem", "proxy CA key")
	flag.StringVar(&app.Config.Addr, "addr", "", "proxy listen host")
	flag.StringVar(&app.Config.Port, "port", "8080", "proxy listen port")
	flag.StringVar(&app.Config.TLSClient, "client", "Golang", "utls client")
	flag.StringVar(&app.Config.TLSVersion, "version", "0", "utls client version")
	flag.StringVar(&app.Config.FingerprintConfig, "fingerprint-config", "", "JSON file to hot-reload utls client/version")
	flag.StringVar(&app.Config.Upstream, "upstream", "", "upstream proxy, e.g. 127.0.0.1:1080, socks5 only")
	flag.BoolVar(&app.Config.Debug, "debug", false, "enable debug")
	flag.Parse()
}

func (app *App) configureLogging() {
	if app.Config.Debug {
		cflog.Level = cflog.LevelDebug
	}
}

func (app *App) ensureCA() {
	if !fileExists(app.Config.Cert) || !fileExists(app.Config.Key) {
		if fileExists(app.Config.Cert) {
			log.Println("found CA cert, but no corresponding key")
			os.Exit(-1)
		} else if fileExists(app.Config.Key) {
			log.Println("found CA key, but no corresponding cert")
			os.Exit(-1)
		}

		log.Println("CA cert and key do not exist, generating")
		err := app.CA.Generate(app.Config.Cert, app.Config.Key)
		if err != nil {
			log.Fatal("Failed generating CA", err)
		}
	}
}

func (app *App) loadExistingCA() error {
	return app.CA.Load(app.Config.Cert, app.Config.Key)
}

func (app *App) generateSessionKey() error {
	return app.SessionKey.Generate()
}

func (app *App) configureTLSFingerprint() {
	if app.Config.FingerprintConfig != "" {
		if err := app.TLSFingerprints.WatchFile(context.Background(), app.Config.FingerprintConfig, 2*time.Second); err != nil {
			log.Fatal("Failed loading fingerprint config", err)
		}
	} else if err := app.TLSFingerprints.SetValidated(TLSFingerprint{
		Client:  app.Config.TLSClient,
		Version: app.Config.TLSVersion,
	}); err != nil {
		log.Fatal("Failed configuring TLS fingerprint", err)
	}
}

func (app *App) buildProxy() *Proxy {
	dialer, err := NewUpstreamDialer(app.Config.Upstream, time.Second*10)
	if err != nil {
		log.Fatal(err)
	}
	app.setUpstreamDialer(dialer)

	return NewProxy(dialer.Dial, tunnelConnect, dialer.Transport)
}

func (app *App) serve(proxy *Proxy) {
	listener, err := net.Listen("tcp", app.Config.Addr+":"+app.Config.Port)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Handler: proxy,
	}

	fmt.Printf(
		"HTTP/SOCKS5 Proxy Server listen at %s:%s, with tls fingerprint %s %s\n",
		app.Config.Addr, app.Config.Port, app.configuredTLSFingerprint().Version, app.configuredTLSFingerprint().Client,
	)
	err = server.Serve(newMixedProxyListener(listener, proxy))
	if err != nil {
		log.Fatal(err)
		os.Exit(-1)
	}
}

func (app *App) setUpstreamDialer(dialer *UpstreamDialer) {
	if app.upstreamDialer == nil {
		return
	}
	*app.upstreamDialer = dialer
}

func (app *App) configuredTLSFingerprint() TLSFingerprint {
	if fingerprint, ok := app.TLSFingerprints.Get(); ok {
		return fingerprint
	}

	return TLSFingerprint{
		Client:  app.Config.TLSClient,
		Version: app.Config.TLSVersion,
	}
}
