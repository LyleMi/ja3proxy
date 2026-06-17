package main

import (
	"bufio"
	"net"
	"sync"
)

const defaultHTTPConnBack = 64

type mixedProxyListener struct {
	base      net.Listener
	proxy     *Proxy
	httpConns chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func newMixedProxyListener(base net.Listener, proxy *Proxy) net.Listener {
	listener := &mixedProxyListener{
		base:      base,
		proxy:     proxy,
		httpConns: make(chan net.Conn, defaultHTTPConnBack),
		done:      make(chan struct{}),
	}
	go listener.acceptLoop()
	return listener
}

func (listener *mixedProxyListener) Accept() (net.Conn, error) {
	select {
	case conn := <-listener.httpConns:
		return conn, nil
	case <-listener.done:
		return nil, net.ErrClosed
	}
}

func (listener *mixedProxyListener) Close() error {
	var err error
	listener.closeOnce.Do(func() {
		close(listener.done)
		err = listener.base.Close()
	})
	return err
}

func (listener *mixedProxyListener) Addr() net.Addr {
	return listener.base.Addr()
}

func (listener *mixedProxyListener) acceptLoop() {
	for {
		conn, err := listener.base.Accept()
		if err != nil {
			_ = listener.Close()
			return
		}
		go listener.route(conn)
	}
}

func (listener *mixedProxyListener) route(conn net.Conn) {
	reader := bufio.NewReader(conn)
	first, err := reader.Peek(1)
	if err != nil {
		conn.Close()
		return
	}

	bufferedConn := &bufferedReadConn{
		Conn:   conn,
		reader: reader,
	}
	if first[0] == socks5Version {
		listener.proxy.handleSOCKS5(bufferedConn)
		return
	}

	select {
	case listener.httpConns <- bufferedConn:
	case <-listener.done:
		conn.Close()
	}
}
