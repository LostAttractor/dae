/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

type ConnSnifferInterface interface {
	net.Conn
	SniffTcp() (string, error)
	WriteBufferedTo(io.Writer) error
}

type ConnSniffer struct {
	net.Conn
	*Sniffer
}

type ConnSnifferCloseWriter struct {
	*ConnSniffer
}

func (c *ConnSnifferCloseWriter) CloseWrite() error {
	return c.Conn.(netproxy.CloseWriter).CloseWrite()
}

func NewConnSniffer(conn net.Conn, timeout time.Duration) ConnSnifferInterface {
	s := &ConnSniffer{
		Conn:    conn,
		Sniffer: NewStreamSniffer(conn, timeout),
	}
	if _, ok := conn.(netproxy.CloseWriter); ok {
		return &ConnSnifferCloseWriter{
			ConnSniffer: s,
		}
	}
	return s
}

// WriteBufferedTo writes the buffered sniff bytes exactly once without
// reading from the underlying connection.
func (s *ConnSniffer) WriteBufferedTo(w io.Writer) error {
	<-s.dataReady

	s.readMu.Lock()
	buf := s.buf
	s.buf = nil
	s.readMu.Unlock()

	if buf == nil {
		return nil
	}
	defer pool.PutBytesBuffer(buf)
	_, err := buf.WriteTo(w)
	return err
}

func (s *ConnSniffer) Read(p []byte) (n int, err error) {
	return s.Sniffer.Read(p)
}

func (s *ConnSniffer) Close() error {
	return errors.Join(s.Conn.Close(), s.Sniffer.Close())
}
