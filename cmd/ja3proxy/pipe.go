package main

import (
	"io"
	"log"
	"net"
)

func junction(destConn net.Conn, clientConn net.Conn) {
	chDone := make(chan struct{}, 2)

	go func() {
		copyAndClose(destConn, clientConn, destConn, "copy client to dest error:")
		chDone <- struct{}{}
	}()

	go func() {
		copyAndClose(clientConn, destConn, clientConn, "copy dest to client error:")
		chDone <- struct{}{}
	}()

	// wait for both copy ops to complete
	<-chDone
	<-chDone
}

func copyAndClose(dst io.Writer, src io.Reader, closeConn io.Closer, logPrefix string) {
	defer closeConn.Close()

	if _, err := io.Copy(dst, src); err != nil {
		log.Println(logPrefix, err)
	}
}
