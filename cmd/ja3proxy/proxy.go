package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

const connectEstablishedResponse = "HTTP/1.1 200 Connection Established\r\n\r\n"

type bufferedReadConn struct {
	net.Conn
	reader *bufio.Reader
}

func (conn *bufferedReadConn) Read(p []byte) (int, error) {
	if conn.reader.Buffered() > 0 {
		return conn.reader.Read(p)
	}
	return conn.Conn.Read(p)
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
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

	clientConn, clientRW, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Println("Hijack error: ", err)
		return
	}

	tunnelClientConn := clientConn
	if clientRW.Reader.Buffered() > 0 {
		tunnelClientConn = &bufferedReadConn{
			Conn:   clientConn,
			reader: clientRW.Reader,
		}
	}

	if _, err := io.WriteString(clientRW, connectEstablishedResponse); err != nil {
		destConn.Close()
		clientConn.Close()
		log.Println("CONNECT response write error: ", err)
		return
	}
	if err := clientRW.Flush(); err != nil {
		destConn.Close()
		clientConn.Close()
		log.Println("CONNECT response flush error: ", err)
		return
	}

	go p.connect(strings.Split(r.Host, ":")[0], destConn, tunnelClientConn)
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

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
