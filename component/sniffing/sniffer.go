/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
	"github.com/daeuniverse/outbound/pool"
)

const (
	packetSniffingMaxBufferedBytes = 64 * 1024
	packetSniffingMaxPackets       = 32
)

type Sniffer struct {
	// Stream
	stream  bool
	r       io.Reader
	ctx     context.Context
	cancel  func()
	pending <-chan streamReadResult

	// Common
	sniffed   string
	buf       *bytes.Buffer
	dataReady chan struct{}
	dataError error
	readMu    sync.Mutex

	// Packet
	data         [][]byte
	needMore     bool
	packetBytes  int
	packetCount  int
	packetLimit  bool
	quicNextRead int
	quicCryptos  *quicutils.CryptoReassembler
}

type streamReadResult struct {
	data []byte
	err  error
}

func NewStreamSniffer(r io.Reader, timeout time.Duration) *Sniffer {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	buffer := pool.GetBytesBuffer()
	buffer.Grow(AssumedTlsClientHelloMaxLength)
	buffer.Reset()
	return &Sniffer{
		stream:    true,
		r:         r,
		buf:       buffer,
		dataReady: make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}
}

func NewPacketSniffer(data []byte) *Sniffer {
	buffer := pool.GetBytesBuffer()
	buffer.Write(data)
	s := &Sniffer{
		buf:       buffer,
		data:      [][]byte{buffer.Bytes()},
		dataReady: make(chan struct{}),
	}
	if len(data) != 0 {
		s.packetBytes = len(data)
		s.packetCount = 1
		s.packetLimit = len(data) > packetSniffingMaxBufferedBytes
	}
	return s
}

type sniff func() (d string, err error)

func sniffGroup(sniffs ...sniff) (d string, err error) {
	for _, sniffer := range sniffs {
		d, err = sniffer()
		if err == nil {
			return NormalizeDomain(d), nil
		}
		if err != ErrNotApplicable {
			return "", err
		}
	}
	return "", ErrNotApplicable
}

func (s *Sniffer) readStreamOnce() error {
	if s.dataError != nil {
		close(s.dataReady)
		return s.dataError
	}
	if conn, ok := s.r.(net.Conn); ok {
		return s.readConnOnce(conn)
	}

	defer close(s.dataReady)
	if s.pending == nil {
		result := make(chan streamReadResult, 1)
		s.pending = result
		go func() {
			buf := make([]byte, consts.EthernetMtu)
			n, err := s.r.Read(buf)
			result <- streamReadResult{data: buf[:n], err: err}
		}()
	}
	select {
	case read := <-s.pending:
		s.pending = nil
		if len(read.data) > 0 {
			s.buf.Write(read.data)
		}
		s.dataError = read.err
		if read.err != nil && len(read.data) == 0 {
			return read.err
		}
		return nil
	case <-s.ctx.Done():
		return fmt.Errorf("%w: %w", ErrNotApplicable, context.DeadlineExceeded)
	}
}

func (s *Sniffer) readConnOnce(conn net.Conn) error {
	defer close(s.dataReady)
	if err := s.ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrNotApplicable, context.DeadlineExceeded)
	}

	deadline, _ := s.ctx.Deadline()
	if err := conn.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("%w: set read deadline: %v", ErrNotApplicable, err)
	}
	defer func() {
		// The sniffing deadline must not affect normal reads or direct handoff.
		_ = conn.SetReadDeadline(time.Time{})
	}()
	buf := pool.GetBuffer(consts.EthernetMtu)
	defer pool.PutBuffer(buf)
	n, err := conn.Read(buf)
	if n > 0 {
		s.buf.Write(buf[:n])
	}
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			if n > 0 {
				return nil
			}
			return fmt.Errorf("%w: %w", ErrNotApplicable, context.DeadlineExceeded)
		}
		s.dataError = err
		if n > 0 {
			return nil
		}
	}
	return err
}

func (s *Sniffer) SniffTcp() (d string, err error) {
	if s.sniffed != "" {
		return s.sniffed, nil
	}
	defer func() {
		if err == nil {
			s.sniffed = d
		}
	}()
	s.readMu.Lock()
	defer s.readMu.Unlock()
	var oerr error
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %w", oerr, err)
		}
	}()
	for {
		if s.stream {
			if err := s.readStreamOnce(); err != nil {
				return "", err
			}
		} else {
			close(s.dataReady)
		}

		if s.buf.Len() == 0 {
			return "", ErrNotApplicable
		}

		d, err = sniffGroup(
			// Most sniffable traffic is TLS, thus we sniff it first.
			s.SniffTls,
			s.SniffHttp,
		)
		if errors.Is(err, ErrNeedMore) {
			oerr = err
			s.dataReady = make(chan struct{})
			continue
		}
		return d, err
	}
}

func (s *Sniffer) SniffUdp() (d string, isQuic bool, err error) {
	if s.sniffed != "" {
		return s.sniffed, s.quicNextRead != 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()

	// Always ready.
	select {
	case <-s.dataReady:
	default:
		close(s.dataReady)
	}

	if s.buf.Len() == 0 || s.packetLimit {
		return "", s.quicNextRead != 0, ErrNotApplicable
	}
	d, err = sniffGroup(s.sniffQuicLocked)
	if err == nil {
		s.sniffed = d
	}
	return d, s.quicNextRead != 0, err
}

func (s *Sniffer) AppendData(data []byte) {
	s.needMore = false
	if !s.stream && (s.packetCount >= packetSniffingMaxPackets || s.packetBytes+len(data) > packetSniffingMaxBufferedBytes) {
		// Retain the triggering datagram so the caller can process it normally
		// after replaying earlier packets, then stop this sniffing session.
		s.packetLimit = true
	}
	ori := s.buf.Len()
	s.buf.Write(data)
	s.data = append(s.data, s.buf.Bytes()[ori:])
	s.packetBytes += len(data)
	s.packetCount++
}

func (s *Sniffer) Data() [][]byte {
	return s.data
}

func (s *Sniffer) NeedMore() bool {
	return s.needMore
}

func (s *Sniffer) Read(p []byte) (n int, err error) {
	<-s.dataReady

	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.pending != nil {
		read := <-s.pending
		s.pending = nil
		if len(read.data) > 0 {
			s.buf.Write(read.data)
		}
		s.dataError = read.err
	}

	if s.buf != nil && s.buf.Len() > 0 {
		// Read buf first.
		n, _ = s.buf.Read(p)
		if s.buf.Len() == 0 && s.dataError != nil {
			return n, s.dataError
		}
		return n, nil
	}
	if s.dataError != nil {
		return 0, s.dataError
	}
	if !s.stream {
		return 0, io.EOF
	}
	return s.r.Read(p)
}

func (s *Sniffer) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	conn, isConn := s.r.(net.Conn)
	if isConn {
		_ = conn.SetReadDeadline(time.Now())
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if isConn {
		_ = conn.SetReadDeadline(time.Time{})
	}
	// Packet replay only aliases buf; the QUIC reassembly is private to the sniffer.
	quicutils.ReleaseCryptoReassembler(s.quicCryptos)
	s.quicCryptos = nil
	if s.pending == nil && s.buf != nil && s.buf.Len() == 0 {
		pool.PutBytesBuffer(s.buf)
		s.buf = nil
	}
	return nil
}
