package tunnel

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/certstore"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/logutil"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/pipe"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/upstreamtls"
	utls "github.com/refraction-networking/utls"
)

type TunnelHandler struct {
	Debug               bool
	CA                  *certstore.CertificateAuthority
	SessionKey          *certstore.SessionKeyHelper
	TLSFingerprints     *fingerprint.TLSFingerprintStore
	UpstreamTLSProfiles *upstreamtls.UpstreamTLSProfileStore
	DefaultTLSClient    string
	DefaultTLSVersion   string
}

func (handler *TunnelHandler) configuredTLSFingerprint() fingerprint.TLSFingerprint {
	if handler != nil && handler.TLSFingerprints != nil {
		if fp, ok := handler.TLSFingerprints.Get(); ok {
			return fp
		}
	}
	if handler != nil {
		return fingerprint.TLSFingerprint{
			Client:  handler.DefaultTLSClient,
			Version: handler.DefaultTLSVersion,
		}
	}

	return fingerprint.TLSFingerprint{
		Client:  utls.HelloGolang.Client,
		Version: utls.HelloGolang.Version,
	}
}

func (handler *TunnelHandler) configuredUpstreamTLSProfile(host string) upstreamtls.UpstreamTLSProfile {
	if handler != nil && handler.UpstreamTLSProfiles != nil {
		if profile, ok := handler.UpstreamTLSProfiles.Get(host); ok {
			return profile
		}
	}
	return upstreamtls.ProfileFromFingerprint(handler.configuredTLSFingerprint())
}

type upstreamTLSConn struct {
	net.Conn
	negotiatedProtocol string
}

func (conn *upstreamTLSConn) NegotiatedProtocol() string {
	if conn == nil {
		return ""
	}
	return conn.negotiatedProtocol
}

func (handler *TunnelHandler) wrapUpstreamTLS(conn net.Conn, routeHost string, serverName string, nextProtos []string) (*upstreamTLSConn, error) {
	profile := handler.configuredUpstreamTLSProfile(routeHost)
	switch upstreamtls.NormalizeProtocol(profile.Protocol) {
	case upstreamtls.ProtocolUTLS:
		uTLSConn, err := handler.utlsWrap(conn, serverName, nextProtos, fingerprint.TLSFingerprint{
			Client:  profile.Client,
			Version: profile.Version,
		})
		if err != nil {
			return nil, err
		}
		return &upstreamTLSConn{
			Conn:               uTLSConn,
			negotiatedProtocol: uTLSConn.ConnectionState().NegotiatedProtocol,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported upstream TLS protocol %q", profile.Protocol)
	}
}

func (handler *TunnelHandler) customTLSWrap(conn net.Conn, sni string, nextProtos []string) (*utls.UConn, error) {
	return handler.utlsWrap(conn, sni, nextProtos, handler.configuredTLSFingerprint())
}

func (handler *TunnelHandler) utlsWrap(conn net.Conn, sni string, nextProtos []string, fp fingerprint.TLSFingerprint) (*utls.UConn, error) {
	clientHelloID := utls.ClientHelloID{
		Client: fp.Client, Version: fp.Version, Seed: nil, Weights: nil,
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
		case *utls.ApplicationSettingsExtensionNew:
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

func (handler *TunnelHandler) Connect(sni string, destConn net.Conn, clientConn net.Conn) {
	defer destConn.Close()
	defer clientConn.Close()
	var destTLSConn *upstreamTLSConn
	routeHost := sni
	logger := logutil.WithComponent("tls_tunnel", "sni", sni)

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

			destTLSConn, err = handler.wrapUpstreamTLS(destConn, routeHost, serverName, upstreamALPN(hello.SupportedProtos))
			if err != nil {
				return nil, err
			}

			return &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{tlsCert},
				NextProtos:         clientALPN(destTLSConn.NegotiatedProtocol()),
			}, nil
		},
	}

	clientTLSConn := tls.Server(
		clientConn,
		config,
	)
	err := clientTLSConn.Handshake()
	if err != nil {
		logger.Warn("client TLS handshake failed", "err", err)
		return
	}

	if destTLSConn == nil {
		logger.Error("upstream TLS connection was not established")
		return
	}

	if handler != nil && handler.Debug {
		pipe.DebugJunction(destTLSConn, clientTLSConn)
	} else {
		pipe.Junction(destTLSConn, clientTLSConn)
	}
}
