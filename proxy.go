package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func customTLSWrap(conn net.Conn, sni string) (*utls.UConn, error) {
	clientHelloID := utls.ClientHelloID{
		Client: Config.TLSClient, Version: Config.TLSVersion, Seed: nil, Weights: nil,
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

	// 解析请求头中的代理配置
	proxyConfig := parseRequestProxyConfig(r)
	
	// 去除自定义请求头，避免传递给目标服务器
	cleanCustomHeaders(r)
	
	// 创建动态拨号器
	dialer, err := createDynamicDialer(proxyConfig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Println("Failed to create dynamic dialer: ", err)
		return
	}

	destConn, err := dialer.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Println("Tunneling err: ", err)
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
		log.Println("Hijack error: ", err)
	}
	go connect(strings.Split(r.Host, ":")[0], destConn, clientConn)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	// 解析请求头中的代理配置
	proxyConfig := parseRequestProxyConfig(req)
	
	// 去除自定义请求头，避免传递给目标服务器
	cleanCustomHeaders(req)
	
	// 处理强制HTTPS升级
	if proxyConfig.ForceHTTPS && req.URL.Scheme == "http" {
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
	}
	
	// 创建自定义传输器
	transport := createCustomTransport(proxyConfig)
	
	resp, err := transport.RoundTrip(req)
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
		fmt.Println("TLS handshake failed: ", err)
		return
	}

	tlsCert, err := generateCertificate(sni)
	if err != nil {
		fmt.Println("Error generating certificate: ", err)
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{tlsCert},
	}

	state := destTLSConn.ConnectionState()
	protocols := state.NegotiatedProtocol

	if protocols == "h2" {
		config.NextProtos = []string{"h2", "http/1.1"}
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

// createDynamicDialer 根据请求配置创建动态拨号器
func createDynamicDialer(config *RequestProxyConfig) (proxy.Dialer, error) {
	if config.ProxyURL == "" {
		// 使用默认拨号器，需要包装成 proxy.Dialer 接口
		return &net.Dialer{Timeout: config.Timeout}, nil
	}
	
	// 创建代理拨号器
	dialer, err := NewUpstreamDialer(config.ProxyURL, config.Timeout)
	if err != nil {
		return nil, err
	}
	
	return dialer, nil
}

// createCustomTransport 根据请求配置创建自定义传输器
func createCustomTransport(config *RequestProxyConfig) *http.Transport {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // 忽略证书验证
		},
	}
	
	// 如果指定了代理，设置代理
	if config.ProxyURL != "" {
		if proxyURL, err := url.Parse(config.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		} else if Config.Debug {
			log.Printf("Failed to parse proxy URL %s: %v, using default proxy", config.ProxyURL, err)
		}
	}
	
	return transport
}
