package main

import (
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

type UpstreamDialer struct {
	dialer proxy.Dialer
}

func NewUpstreamDialer(upstreamAddr string, timeout time.Duration) (*UpstreamDialer, error) {
	var dialer proxy.Dialer

	if upstreamAddr != "" {
		parsedURL, err := url.Parse(upstreamAddr)
		if err != nil {
			return nil, err
		}

		// 根据协议类型选择不同的代理
		switch parsedURL.Scheme {
		case "http", "https":
			// HTTP 代理
			httpDialer, err := proxy.FromURL(parsedURL, proxy.Direct)
			if err != nil {
				return nil, err
			}
			dialer = httpDialer

			// set upstream proxy for http connections
			defaultTransport := http.DefaultTransport.(*http.Transport).Clone()
			defaultTransport.Proxy = func(req *http.Request) (*url.URL, error) {
				return parsedURL, nil
			}
			http.DefaultTransport = defaultTransport

		case "socks5":
			// SOCKS5 代理（原有逻辑）
			user := parsedURL.User.Username()
			password, _ := parsedURL.User.Password()
			socksDialer, err := proxy.SOCKS5(
				"tcp", parsedURL.Host,
				&proxy.Auth{User: user, Password: password},
				proxy.Direct,
			)
			if err != nil {
				return nil, err
			}
			dialer = socksDialer

			// set upstream proxy for http connections
			defaultTransport := http.DefaultTransport.(*http.Transport).Clone()
			defaultTransport.Proxy = func(req *http.Request) (*url.URL, error) {
				return parsedURL, nil
			}
			http.DefaultTransport = defaultTransport

		default:
			// 默认当作 SOCKS5 处理（向后兼容）
			user := parsedURL.User.Username()
			password, _ := parsedURL.User.Password()
			socksDialer, err := proxy.SOCKS5(
				"tcp", parsedURL.Host,
				&proxy.Auth{User: user, Password: password},
				proxy.Direct,
			)
			if err != nil {
				return nil, err
			}
			dialer = socksDialer

			// set upstream proxy for http connections
			defaultTransport := http.DefaultTransport.(*http.Transport).Clone()
			defaultTransport.Proxy = func(req *http.Request) (*url.URL, error) {
				return parsedURL, nil
			}
			http.DefaultTransport = defaultTransport
		}
	} else {
		dialer = &net.Dialer{Timeout: timeout}
	}

	return &UpstreamDialer{dialer: dialer}, nil
}

func (u *UpstreamDialer) Dial(network, addr string) (net.Conn, error) {
	return u.dialer.Dial(network, addr)
}
