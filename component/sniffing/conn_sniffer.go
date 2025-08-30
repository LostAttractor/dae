/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"net"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type ConnSnifferInterface interface {
	net.Conn
	SniffTcp() (string, error)
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

func (s *ConnSniffer) Read(p []byte) (n int, err error) {
	return s.Sniffer.Read(p)
}

func (s *ConnSniffer) Close() error {
	return errors.Join(s.Conn.Close(), s.Sniffer.Close())
}
