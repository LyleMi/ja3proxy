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
	chDone := make(chan struct{}, 2)

	go func() {
		writer := &DebugWriter{
			Name: clientConn.RemoteAddr().String(),
			Conn: destConn,
		}

		copyAndClose(writer, clientConn, destConn, "copy client to dest error:")
		chDone <- struct{}{}
	}()

	go func() {
		writer := &DebugWriter{
			Name: destConn.RemoteAddr().String(),
			Conn: clientConn,
		}

		copyAndClose(writer, destConn, clientConn, "copy dest to client error:")
		chDone <- struct{}{}
	}()

	// wait for both copy ops to complete
	<-chDone
	<-chDone
}
