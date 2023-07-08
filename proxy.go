package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

var (
	cert       string
	key        string
	tlsClient  string
	tlsVersion string
)

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func customTLSWrap(conn net.Conn, sni string) (net.Conn, error) {
	clientHelloID := utls.ClientHelloID{
		tlsClient, tlsVersion, nil, nil,
	}

	uTLSConn := utls.UClient(
		conn,
		&utls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		},
		clientHelloID,
	)
	if err := uTLSConn.Handshake(); err != nil {
		return nil, err
	}
	return uTLSConn, nil
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	log.Printf("proxy to %s", r.Host)
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Println("Tunneling err", err)
		return
	}
	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		log.Println("Hijacking not supported")
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Println("Hijack error", err)
	}
	go connect(strings.Split(r.Host, ":")[0], destConn, clientConn)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
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

func connect(sni string, destConn net.Conn, clientConn net.Conn) {
	defer destConn.Close()
	defer clientConn.Close()
	destTLSConn, err := customTLSWrap(destConn, sni)
	if err != nil {
		fmt.Println("TLS handshake failed:", err)
		return
	}

	cert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		log.Fatal(err)
	}

	clientTLSConn := tls.Server(
		clientConn,
		&tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{cert},
		},
	)
	err = clientTLSConn.Handshake()
	if err != nil {
		log.Println("Failed to perform TLS handshake:", err)
		return
	}

	junction(destTLSConn, clientTLSConn)
}

func junction(destConn net.Conn, clientConn net.Conn) {
	chDone := make(chan bool)

	go func() {
		_, err := io.Copy(destConn, clientConn)
		if err != nil {
			log.Println("copy dest to client error", err)
		}
		chDone <- true
	}()

	go func() {
		_, err := io.Copy(clientConn, destConn)
		if err != nil {
			log.Println("copy client to dest error", err)
		}
		chDone <- true
	}()

	<-chDone
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func main() {
	var (
		addr string
		port string
	)
	flag.StringVar(&cert, "cert", "cert.pem", "proxy tls cert")
	flag.StringVar(&key, "key", "key.pem", "proxy tls key")
	flag.StringVar(&addr, "addr", "", "proxy host")
	flag.StringVar(&port, "port", "8080", "proxy port")
	flag.StringVar(&tlsClient, "client", "Golang", "utls client")
	flag.StringVar(&tlsVersion, "version", "0", "utls client version")
	flag.Parse()

	if !fileExists(cert) || !fileExists(key) {
		log.Println("cert not exists, generate")
		cert = ""
		generateCertificate()
	}

	server := &http.Server{
		Addr: addr + ":" + port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
	}

	fmt.Println("HTTP Proxy Server started at localhost Port:" + port)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
		os.Exit(-1)
	}
}
