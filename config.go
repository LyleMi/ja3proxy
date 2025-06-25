package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"strconv"
	"time"
	"net/http"
	"net/url"
	"log"
)

type RunningConfig struct {
	Debug      bool
	Addr       string
	Port       string
	TLSVersion string
	TLSClient  string
	Cert       string
	Key        string
	Upstream   string
}

type RequestProxyConfig struct {
	Timeout    time.Duration
	ProxyURL   string
	ForceHTTPS bool
}

type CertificateAuthority struct {
	tlsCert  tls.Certificate
	x509Cert *x509.Certificate
}

type SessionKeyHelper struct {
	privateKey *ecdsa.PrivateKey
	PEMBlock   []byte
}

var (
	Config       RunningConfig
	CustomDialer *UpstreamDialer
	CA           CertificateAuthority
	SessionKey   SessionKeyHelper
)

// parseRequestProxyConfig 从请求头解析代理配置
func parseRequestProxyConfig(req *http.Request) *RequestProxyConfig {
	config := &RequestProxyConfig{
		Timeout:    10 * time.Second, // 默认10秒
		ProxyURL:   "",
		ForceHTTPS: false,
	}

	// 解析超时时间
	if timeoutStr := req.Header.Get("tls-timeout"); timeoutStr != "" {
		if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
			config.Timeout = time.Duration(timeout) * time.Second
		} else if Config.Debug {
			log.Printf("Invalid tls-timeout value: %s, using default", timeoutStr)
		}
	}

	// 解析代理URL
	if proxyURL := req.Header.Get("tls-proxy"); proxyURL != "" {
		// 验证代理URL格式
		if _, err := url.Parse(proxyURL); err == nil {
			config.ProxyURL = proxyURL
		} else if Config.Debug {
			log.Printf("Invalid tls-proxy URL: %s, ignoring", proxyURL)
		}
	}

	// 解析是否强制HTTPS
	if forceHTTPS := req.Header.Get("tls-https"); forceHTTPS != "" {
		config.ForceHTTPS = forceHTTPS == "true"
	}

	return config
}

// cleanCustomHeaders 清理自定义请求头，避免传递给目标服务器
func cleanCustomHeaders(req *http.Request) {
	req.Header.Del("tls-timeout")
	req.Header.Del("tls-proxy")
	req.Header.Del("tls-https")
}
