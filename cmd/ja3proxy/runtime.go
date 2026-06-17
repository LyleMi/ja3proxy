package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
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

func (app *App) run() error {
	app.parseFlags()
	app.configureLogging()
	if err := app.ensureCA(); err != nil {
		return err
	}
	if err := app.loadExistingCA(); err != nil {
		return fmt.Errorf("failed loading CA: %w", err)
	}
	if err := app.generateSessionKey(); err != nil {
		return fmt.Errorf("failed generating session key: %w", err)
	}
	if err := app.configureTLSFingerprint(); err != nil {
		return err
	}

	proxy, err := app.buildProxy()
	if err != nil {
		return err
	}
	return app.serve(proxy)
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

func (app *App) ensureCA() error {
	if !fileExists(app.Config.Cert) || !fileExists(app.Config.Key) {
		if fileExists(app.Config.Cert) {
			return fmt.Errorf("found CA cert %q, but no corresponding key %q", app.Config.Cert, app.Config.Key)
		} else if fileExists(app.Config.Key) {
			return fmt.Errorf("found CA key %q, but no corresponding cert %q", app.Config.Key, app.Config.Cert)
		}

		log.Println("CA cert and key do not exist, generating")
		if err := app.CA.Generate(app.Config.Cert, app.Config.Key); err != nil {
			return fmt.Errorf("failed generating CA: %w", err)
		}
	}
	return nil
}

func (app *App) loadExistingCA() error {
	return app.CA.Load(app.Config.Cert, app.Config.Key)
}

func (app *App) generateSessionKey() error {
	return app.SessionKey.Generate()
}

func (app *App) configureTLSFingerprint() error {
	if app.Config.FingerprintConfig != "" {
		if err := app.TLSFingerprints.WatchFile(context.Background(), app.Config.FingerprintConfig, 2*time.Second); err != nil {
			return fmt.Errorf("failed loading fingerprint config: %w", err)
		}
	} else if err := app.TLSFingerprints.SetValidated(TLSFingerprint{
		Client:  app.Config.TLSClient,
		Version: app.Config.TLSVersion,
	}); err != nil {
		return fmt.Errorf("failed configuring TLS fingerprint: %w", err)
	}
	return nil
}

func (app *App) buildProxy() (*Proxy, error) {
	dialer, err := NewUpstreamDialer(app.Config.Upstream, time.Second*10)
	if err != nil {
		return nil, fmt.Errorf("configure upstream proxy: %w", err)
	}
	app.setUpstreamDialer(dialer)

	return NewProxy(dialer.Dial, app.tunnelHandler().Connect, dialer.Transport), nil
}

func (app *App) serve(proxy *Proxy) error {
	listener, err := net.Listen("tcp", app.Config.Addr+":"+app.Config.Port)
	if err != nil {
		return fmt.Errorf("listen on %s:%s: %w", app.Config.Addr, app.Config.Port, err)
	}
	server := &http.Server{
		Handler: proxy,
	}

	fmt.Printf(
		"HTTP/SOCKS5 Proxy Server listen at %s:%s, with tls fingerprint %s %s\n",
		app.Config.Addr, app.Config.Port, app.configuredTLSFingerprint().Version, app.configuredTLSFingerprint().Client,
	)
	if err := server.Serve(newMixedProxyListener(listener, proxy)); err != nil {
		return fmt.Errorf("serve proxy: %w", err)
	}
	return nil
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

func (app *App) tunnelHandler() *TunnelHandler {
	return &TunnelHandler{
		Debug:             app.Config.Debug,
		CA:                app.CA,
		SessionKey:        app.SessionKey,
		TLSFingerprints:   app.TLSFingerprints,
		DefaultTLSClient:  app.Config.TLSClient,
		DefaultTLSVersion: app.Config.TLSVersion,
	}
}
