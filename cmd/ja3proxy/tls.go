package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"

	utls "github.com/refraction-networking/utls"
)

type TunnelHandler struct {
	Debug             bool
	CA                *CertificateAuthority
	SessionKey        *SessionKeyHelper
	TLSFingerprints   *TLSFingerprintStore
	DefaultTLSClient  string
	DefaultTLSVersion string
}

func newDefaultTunnelHandler() *TunnelHandler {
	return &TunnelHandler{
		Debug:             Config.Debug,
		CA:                &CA,
		SessionKey:        &SessionKey,
		TLSFingerprints:   &defaultTLSFingerprintStore,
		DefaultTLSClient:  Config.TLSClient,
		DefaultTLSVersion: Config.TLSVersion,
	}
}

func (handler *TunnelHandler) configuredTLSFingerprint() TLSFingerprint {
	if handler != nil && handler.TLSFingerprints != nil {
		if fingerprint, ok := handler.TLSFingerprints.Get(); ok {
			return fingerprint
		}
	}
	if handler != nil {
		return TLSFingerprint{
			Client:  handler.DefaultTLSClient,
			Version: handler.DefaultTLSVersion,
		}
	}

	return TLSFingerprint{
		Client:  Config.TLSClient,
		Version: Config.TLSVersion,
	}
}

func customTLSWrap(conn net.Conn, sni string, nextProtos []string) (*utls.UConn, error) {
	return newDefaultTunnelHandler().customTLSWrap(conn, sni, nextProtos)
}

func (handler *TunnelHandler) customTLSWrap(conn net.Conn, sni string, nextProtos []string) (*utls.UConn, error) {
	fingerprint := handler.configuredTLSFingerprint()
	clientHelloID := utls.ClientHelloID{
		Client: fingerprint.Client, Version: fingerprint.Version, Seed: nil, Weights: nil,
	}

	tlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         nextProtos,
	}
	uTLSConn := utls.UClient(
		conn,
		tlsConfig,
		clientHelloID,
	)

	if len(nextProtos) > 0 && clientHelloID.Client != utls.HelloGolang.Client {
		spec, err := utls.UTLSIdToSpec(clientHelloID)
		if err == nil {
			limitSpecALPN(&spec, nextProtos)
			uTLSConn = utls.UClient(conn, tlsConfig, utls.HelloCustom)
			if err := uTLSConn.ApplyPreset(&spec); err != nil {
				return nil, err
			}
		}
	}

	if err := uTLSConn.Handshake(); err != nil {
		return nil, err
	}

	return uTLSConn, nil
}

func limitSpecALPN(spec *utls.ClientHelloSpec, nextProtos []string) {
	extensions := make([]utls.TLSExtension, 0, len(spec.Extensions)+1)
	for _, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.ALPNExtension:
			ext.AlpnProtocols = nextProtos
			extensions = append(extensions, extension)
		case *utls.ApplicationSettingsExtension:
			ext.SupportedProtocols = matchingProtocols(ext.SupportedProtocols, nextProtos)
			if len(ext.SupportedProtocols) > 0 {
				extensions = append(extensions, extension)
			}
		default:
			extensions = append(extensions, extension)
		}
	}

	spec.Extensions = extensions
}

func matchingProtocols(supported []string, allowed []string) []string {
	matches := make([]string, 0, len(supported))
	for _, protocol := range supported {
		for _, allowedProtocol := range allowed {
			if protocol == allowedProtocol {
				matches = append(matches, protocol)
				break
			}
		}
	}
	return matches
}

func upstreamALPN(clientProtocols []string) []string {
	if len(clientProtocols) == 0 {
		return []string{"http/1.1"}
	}
	return clientProtocols
}

func clientALPN(upstreamProtocol string) []string {
	if upstreamProtocol != "" {
		return []string{upstreamProtocol}
	}
	return []string{"http/1.1"}
}

func (handler *TunnelHandler) generateCertificate(sni string) (tls.Certificate, error) {
	if handler == nil || handler.CA == nil {
		return tls.Certificate{}, fmt.Errorf("CA certificate has not been loaded")
	}
	if handler.SessionKey == nil {
		return tls.Certificate{}, fmt.Errorf("session key has not been generated")
	}

	return handler.CA.GenerateCertificate(*handler.SessionKey, sni)
}

func connect(sni string, destConn net.Conn, clientConn net.Conn) {
	newDefaultTunnelHandler().Connect(sni, destConn, clientConn)
}

func (handler *TunnelHandler) Connect(sni string, destConn net.Conn, clientConn net.Conn) {
	defer destConn.Close()
	defer clientConn.Close()
	var destTLSConn *utls.UConn

	config := &tls.Config{
		InsecureSkipVerify: true,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName := sni
			if hello.ServerName != "" {
				serverName = hello.ServerName
			}

			tlsCert, err := handler.generateCertificate(serverName)
			if err != nil {
				return nil, fmt.Errorf("generate certificate: %w", err)
			}

			destTLSConn, err = handler.customTLSWrap(destConn, serverName, upstreamALPN(hello.SupportedProtos))
			if err != nil {
				return nil, err
			}

			return &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{tlsCert},
				NextProtos:         clientALPN(destTLSConn.ConnectionState().NegotiatedProtocol),
			}, nil
		},
	}

	clientTLSConn := tls.Server(
		clientConn,
		config,
	)
	err := clientTLSConn.Handshake()
	if err != nil {
		log.Println("Failed to perform TLS handshake: ", err)
		return
	}

	if destTLSConn == nil {
		log.Println("Failed to establish upstream TLS connection")
		return
	}

	if handler != nil && handler.Debug {
		debugJunction(destTLSConn, clientTLSConn)
	} else {
		junction(destTLSConn, clientTLSConn)
	}
}
