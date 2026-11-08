package traffic

import (
	"io"
	"net"
	"net/http"
)

type trafficReadConn struct {
	net.Conn
	session   *TrafficSessionHandle
	direction trafficDirection
}

func (conn *trafficReadConn) Read(p []byte) (int, error) {
	n, err := conn.Conn.Read(p)
	switch conn.direction {
	case trafficDirectionUpload:
		conn.session.AddUpload(n)
	case trafficDirectionDownload:
		conn.session.AddDownload(n)
	}
	return n, err
}

func wrapTrafficTunnel(session *TrafficSessionHandle, destConn net.Conn, clientConn net.Conn) (net.Conn, net.Conn) {
	if session == nil {
		return destConn, clientConn
	}
	return &trafficReadConn{
		Conn:      destConn,
		session:   session,
		direction: trafficDirectionDownload,
	}, &trafficReadConn{
		Conn:      clientConn,
		session:   session,
		direction: trafficDirectionUpload,
	}
}

func WrapTunnel(session *TrafficSessionHandle, destConn net.Conn, clientConn net.Conn) (net.Conn, net.Conn) {
	return wrapTrafficTunnel(session, destConn, clientConn)
}

type trafficReadCloser struct {
	io.ReadCloser
	session *TrafficSessionHandle
}

func WrapReadCloser(session *TrafficSessionHandle, reader io.ReadCloser) io.ReadCloser {
	if session == nil || reader == nil {
		return reader
	}
	return &trafficReadCloser{
		ReadCloser: reader,
		session:    session,
	}
}

func (reader *trafficReadCloser) Read(p []byte) (int, error) {
	n, err := reader.ReadCloser.Read(p)
	reader.session.AddUpload(n)
	return n, err
}

type trafficResponseWriter struct {
	http.ResponseWriter
	session *TrafficSessionHandle
}

func WrapResponseWriter(session *TrafficSessionHandle, writer http.ResponseWriter) http.ResponseWriter {
	if session == nil || writer == nil {
		return writer
	}
	return &trafficResponseWriter{
		ResponseWriter: writer,
		session:        session,
	}
}

func (writer *trafficResponseWriter) Write(p []byte) (int, error) {
	n, err := writer.ResponseWriter.Write(p)
	writer.session.AddDownload(n)
	return n, err
}
