package main

import (
	"encoding/hex"
	"io"
	"log"
	"net"
	"unicode"
)

type DebugWriter struct {
	Name string
	Conn net.Conn
}

func (writer DebugWriter) Write(data []byte) (n int, err error) {
	if unicode.IsPrint(rune(data[0])) {
		log.Printf("%s send %d bytes: \n%s", writer.Name, len(data), string(data))
	} else {
		log.Printf("%s send %d bytes: \n%s", writer.Name, len(data), hex.Dump(data))
	}

	return writer.Conn.Write(data)
}

func debugJunction(destConn net.Conn, clientConn net.Conn) {
	chDone := make(chan bool, 2)

	go func() {
		defer func() {
			destConn.Close()
			chDone <- true
		}()

		writer := &DebugWriter{
			Name: clientConn.RemoteAddr().String(),
			Conn: destConn,
		}

		_, err := io.Copy(writer, clientConn)
		if err != nil {
			log.Println("copy dest to client error:", err)
		}
	}()

	go func() {
		defer func() {
			clientConn.Close()
			chDone <- true
		}()

		writer := &DebugWriter{
			Name: destConn.RemoteAddr().String(),
			Conn: clientConn,
		}

		_, err := io.Copy(writer, destConn)
		if err != nil {
			log.Println("copy client to dest error:", err)
		}
	}()

	// wait for both copy ops to complete
	<-chDone
	<-chDone
}
