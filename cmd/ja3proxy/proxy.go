package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	utls "github.com/refraction-networking/utls"
)

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func customTLSWrap(conn net.Conn, sni string, nextProtos []string) (*utls.UConn, error) {
	clientHelloID := utls.ClientHelloID{
		Client: Config.TLSClient, Version: Config.TLSVersion, Seed: nil, Weights: nil,
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

type Proxy struct {
	Dial      func(network, addr string) (net.Conn, error)
	Connect   func(sni string, destConn net.Conn, clientConn net.Conn)
	Transport http.RoundTripper
}

func NewProxy(
	dial func(network, addr string) (net.Conn, error),
	connect func(sni string, destConn net.Conn, clientConn net.Conn),
	transport http.RoundTripper,
) *Proxy {
	if dial == nil {
		dial = tunnelDial
	}
	if connect == nil {
		connect = tunnelConnect
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &Proxy{
		Dial:      dial,
		Connect:   connect,
		Transport: transport,
	}
}

func defaultProxy() *Proxy {
	return NewProxy(tunnelDial, tunnelConnect, http.DefaultTransport)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleTunneling(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *Proxy) dial(network, addr string) (net.Conn, error) {
	if p != nil && p.Dial != nil {
		return p.Dial(network, addr)
	}
	return tunnelDial(network, addr)
}

func (p *Proxy) connect(sni string, destConn net.Conn, clientConn net.Conn) {
	if p != nil && p.Connect != nil {
		p.Connect(sni, destConn, clientConn)
		return
	}
	tunnelConnect(sni, destConn, clientConn)
}

func (p *Proxy) transport() http.RoundTripper {
	if p != nil && p.Transport != nil {
		return p.Transport
	}
	return http.DefaultTransport
}

func (p *Proxy) handleTunneling(w http.ResponseWriter, r *http.Request) {
	log.Printf("proxy to %s", r.Host)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		log.Println("Hijacking not supported")
		return
	}

	destConn, err := p.dial("tcp", r.Host)

	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Println("Tunneling err: ", err)
		return
	}
	w.WriteHeader(http.StatusOK)

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Println("Hijack error: ", err)
		return
	}
	go p.connect(strings.Split(r.Host, ":")[0], destConn, clientConn)
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	defaultProxy().handleTunneling(w, r)
}

var tunnelDial = func(network, addr string) (net.Conn, error) {
	return CustomDialer.Dial(network, addr)
}

var tunnelConnect = connect

func (p *Proxy) handleHTTP(w http.ResponseWriter, req *http.Request) {
	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""

	resp, err := p.transport().RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	defaultProxy().handleHTTP(w, req)
}

func connect(sni string, destConn net.Conn, clientConn net.Conn) {
	defer destConn.Close()
	defer clientConn.Close()
	var destTLSConn *utls.UConn

	tlsCert, err := generateCertificate(sni)
	if err != nil {
		fmt.Println("Error generating certificate: ", err)
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{tlsCert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			destTLSConn, err = customTLSWrap(destConn, sni, upstreamALPN(hello.SupportedProtos))
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
	err = clientTLSConn.Handshake()
	if err != nil {
		log.Println("Failed to perform TLS handshake: ", err)
		return
	}

	if destTLSConn == nil {
		log.Println("Failed to establish upstream TLS connection")
		return
	}

	if Config.Debug {
		debugJunction(destTLSConn, clientTLSConn)
	} else {
		junction(destTLSConn, clientTLSConn)
	}
}

func junction(destConn net.Conn, clientConn net.Conn) {
	chDone := make(chan bool, 2)

	go func() {
		_, err := io.Copy(destConn, clientConn)
		if err != nil {
			log.Println("copy dest to client error: ", err)
		}
		chDone <- true
	}()

	go func() {
		_, err := io.Copy(clientConn, destConn)
		if err != nil {
			log.Println("copy client to dest error: ", err)
		}
		chDone <- true
	}()

	// wait for both copy ops to complete
	<-chDone
	<-chDone
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
