package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

const (
	socks5Version      = 0x05
	socks5NoAuth       = 0x00
	socks5NoAcceptable = 0xff
	socks5Connect      = 0x01
	socks5Reserved     = 0x00
	socks5IPv4         = 0x01
	socks5Domain       = 0x03
	socks5IPv6         = 0x04
	socks5Succeeded    = 0x00
	socks5GeneralFail  = 0x01
	socks5CommandFail  = 0x07
	socks5AddressFail  = 0x08
	tlsHandshakeRecord = 0x16
	socks5TLSPeekTime  = 100 * time.Millisecond
)

type socks5Request struct {
	command byte
	host    string
	port    uint16
}

func (request socks5Request) addr() string {
	return net.JoinHostPort(request.host, strconv.Itoa(int(request.port)))
}

func (p *Proxy) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	if err := negotiateSOCKS5(conn, reader); err != nil {
		log.Printf("SOCKS5 negotiation error: %v", err)
		return
	}

	request, err := readSOCKS5Request(reader)
	if err != nil {
		_ = writeSOCKS5Reply(conn, socks5AddressFail)
		log.Printf("SOCKS5 request error: %v", err)
		return
	}
	if request.command != socks5Connect {
		_ = writeSOCKS5Reply(conn, socks5CommandFail)
		log.Printf("SOCKS5 unsupported command: %d", request.command)
		return
	}

	destAddr := request.addr()
	log.Printf("socks5 proxy to %s", destAddr)
	destConn, err := p.dial("tcp", destAddr)
	if err != nil {
		_ = writeSOCKS5Reply(conn, socks5GeneralFail)
		log.Printf("SOCKS5 dial error: %v", err)
		return
	}

	if err := writeSOCKS5Reply(conn, socks5Succeeded); err != nil {
		destConn.Close()
		log.Printf("SOCKS5 reply error: %v", err)
		return
	}

	p.handleSOCKS5Tunnel(request.host, request.port, destConn, conn, reader)
}

func negotiateSOCKS5(conn net.Conn, reader *bufio.Reader) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return fmt.Errorf("unsupported version %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == socks5NoAuth {
			_, err := conn.Write([]byte{socks5Version, socks5NoAuth})
			return err
		}
	}

	_, _ = conn.Write([]byte{socks5Version, socks5NoAcceptable})
	return fmt.Errorf("no supported authentication method")
}

func readSOCKS5Request(reader *bufio.Reader) (socks5Request, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return socks5Request{}, err
	}
	if header[0] != socks5Version {
		return socks5Request{}, fmt.Errorf("unsupported version %d", header[0])
	}
	if header[2] != socks5Reserved {
		return socks5Request{}, fmt.Errorf("reserved byte = %d", header[2])
	}

	host, err := readSOCKS5Address(reader, header[3])
	if err != nil {
		return socks5Request{}, err
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return socks5Request{}, err
	}

	return socks5Request{
		command: header[1],
		host:    host,
		port:    binary.BigEndian.Uint16(portBytes),
	}, nil
}

func readSOCKS5Address(reader *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case socks5IPv4:
		addr := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return "", err
		}
		return net.IP(addr).String(), nil
	case socks5Domain:
		length, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		if length == 0 {
			return "", fmt.Errorf("empty domain")
		}
		domain := make([]byte, int(length))
		if _, err := io.ReadFull(reader, domain); err != nil {
			return "", err
		}
		return string(domain), nil
	case socks5IPv6:
		addr := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return "", err
		}
		return net.IP(addr).String(), nil
	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
}

func writeSOCKS5Reply(conn net.Conn, status byte) error {
	_, err := conn.Write([]byte{
		socks5Version,
		status,
		socks5Reserved,
		socks5IPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	})
	return err
}

func (p *Proxy) handleSOCKS5Tunnel(host string, port uint16, destConn net.Conn, clientConn net.Conn, reader *bufio.Reader) {
	if port == 443 {
		p.connect(host, destConn, &bufferedReadConn{
			Conn:   clientConn,
			reader: reader,
		})
		return
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(socks5TLSPeekTime)); err != nil {
		destConn.Close()
		log.Printf("SOCKS5 set read deadline error: %v", err)
		return
	}
	first, err := reader.Peek(1)
	if deadlineErr := clientConn.SetReadDeadline(time.Time{}); deadlineErr != nil {
		destConn.Close()
		log.Printf("SOCKS5 clear read deadline error: %v", deadlineErr)
		return
	}
	if err != nil {
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			destConn.Close()
			log.Printf("SOCKS5 client read error: %v", err)
			return
		}
	}

	tunnelClientConn := &bufferedReadConn{
		Conn:   clientConn,
		reader: reader,
	}
	if len(first) > 0 && first[0] == tlsHandshakeRecord {
		p.connect(host, destConn, tunnelClientConn)
		return
	}

	defer destConn.Close()
	junction(destConn, tunnelClientConn)
}
