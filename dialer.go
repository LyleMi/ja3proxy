package main

import (
	"net"
	"time"

	"golang.org/x/net/proxy"
)

type UpstreamDialer struct {
	dialer proxy.Dialer
}

func NewUpstreamDialer(socksAddr string, timeout time.Duration) (*UpstreamDialer, error) {
	var dialer proxy.Dialer

	if socksAddr != "" {
		socksDialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		dialer = socksDialer
	} else {
		dialer = &net.Dialer{Timeout: timeout}
	}

	return &UpstreamDialer{dialer: dialer}, nil
}

func (u *UpstreamDialer) Dial(network, addr string) (net.Conn, error) {
	return u.dialer.Dial(network, addr)
}
