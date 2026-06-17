package main

import (
	"encoding/hex"
	"log"
	"net"
	"unicode"
)

type DebugWriter struct {
	Name string
	Conn net.Conn
}

func (writer DebugWriter) Write(data []byte) (n int, err error) {
	if len(data) == 0 {
		log.Printf("%s send 0 bytes: \n", writer.Name)
		return writer.Conn.Write(data)
	}

	if unicode.IsPrint(rune(data[0])) {
		log.Printf("%s send %d bytes: \n%s", writer.Name, len(data), string(data))
	} else {
		log.Printf("%s send %d bytes: \n%s", writer.Name, len(data), hex.Dump(data))
	}

	return writer.Conn.Write(data)
}

func debugJunction(destConn net.Conn, clientConn net.Conn) {
	destWriter := &DebugWriter{
		Name: clientConn.RemoteAddr().String(),
		Conn: destConn,
	}
	clientWriter := &DebugWriter{
		Name: destConn.RemoteAddr().String(),
		Conn: clientConn,
	}

	pipeConns(destConn, clientConn, destWriter, clientWriter)
}
