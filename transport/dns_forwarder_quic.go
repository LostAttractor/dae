/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	dns "github.com/daeuniverse/dae-plugin-dns-router/policy"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/quic-go"
	dnsmessage "github.com/miekg/dns"
)

const (
	doqNoError          quic.ApplicationErrorCode = 0x0
	doqProtocolError    quic.ApplicationErrorCode = 0x2
	doqRequestCancelled quic.StreamErrorCode      = 0x3
)

type doqProtocolErrorCause struct{ err error }

func (e *doqProtocolErrorCause) Error() string { return e.err.Error() }

func (e *doqProtocolErrorCause) Unwrap() error { return e.err }

type doqStream interface {
	io.Reader
	io.Writer
	io.Closer
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
}

func newDoqProtocolError(err error) error {
	return &doqProtocolErrorCause{err: err}
}

func validateDoqOptions(msg *dnsmessage.Msg) error {
	for _, section := range [][]dnsmessage.RR{msg.Answer, msg.Ns} {
		for _, rr := range section {
			if rr != nil && rr.Header().Rrtype == dnsmessage.TypeOPT {
				return errors.New("DoQ message contains OPT outside the additional section")
			}
		}
	}
	var opt *dnsmessage.OPT
	for _, rr := range msg.Extra {
		if rr == nil || rr.Header().Rrtype != dnsmessage.TypeOPT {
			continue
		}
		if opt != nil {
			return errors.New("DoQ message contains multiple OPT records")
		}
		var ok bool
		opt, ok = rr.(*dnsmessage.OPT)
		if !ok {
			return errors.New("DoQ message contains malformed OPT record")
		}
		if opt.Hdr.Name != "." {
			return errors.New("DoQ OPT record owner is not the root name")
		}
		paddingCount := 0
		for _, option := range opt.Option {
			if option == nil {
				return errors.New("DoQ message contains a nil EDNS option")
			}
			switch option.Option() {
			case dnsmessage.EDNS0TCPKEEPALIVE:
				return errors.New("DoQ message contains EDNS TCP keepalive")
			case dnsmessage.EDNS0PADDING:
				paddingCount++
			}
		}
		if paddingCount > 1 {
			return errors.New("DoQ message contains multiple EDNS padding options")
		}
	}
	return nil
}

func packDoqQuery(msg *dnsmessage.Msg) (*dnsmessage.Msg, []byte, error) {
	if len(msg.Question) != 0 && (msg.Question[0].Qtype == dnsmessage.TypeAXFR || msg.Question[0].Qtype == dnsmessage.TypeIXFR) {
		return nil, nil, errors.New("DoQ zone transfers are not supported")
	}
	if err := validateDoqOptions(msg); err != nil {
		return nil, nil, err
	}
	if hasDnsTransactionSignature(msg) {
		return nil, nil, errors.New("DoQ forwarder does not support transaction signatures")
	}

	query := msg.Copy()
	query.Id = 0
	unpaddedPayload, err := query.Pack()
	if err != nil {
		return nil, nil, fmt.Errorf("pack DNS packet: %w", err)
	}
	if err := netutils.CheckDnsMessageSize(len(unpaddedPayload)); err != nil {
		return nil, nil, err
	}

	paddedQuery := query.Copy()
	opt := paddedQuery.IsEdns0()
	if opt == nil {
		paddedQuery.SetEdns0(1232, false)
		opt = paddedQuery.IsEdns0()
	}
	options := opt.Option[:0]
	for _, option := range opt.Option {
		if option.Option() != dnsmessage.EDNS0PADDING {
			options = append(options, option)
		}
	}
	opt.Option = options

	payload, err := paddedQuery.Pack()
	if err != nil {
		return nil, nil, fmt.Errorf("pack DNS packet: %w", err)
	}
	// RFC 9250 requires traffic-analysis protection. RFC 8467 padding covers
	// the DNS message itself and excludes the DoQ length prefix.
	const paddingBlockSize = 128
	paddingLen := (paddingBlockSize - (len(payload)+4)%paddingBlockSize) % paddingBlockSize
	maxPaddingLen := consts.MaxDnsMessageSize - len(payload) - 4
	if maxPaddingLen < 0 {
		// There is not enough room for even a zero-length Padding option.
		payload = unpaddedPayload
		paddedQuery = query
		paddingLen = -1
	} else if paddingLen > maxPaddingLen {
		// The next full block exceeds the DNS size limit. Use all remaining
		// space so a near-limit query is still protected by padding.
		paddingLen = maxPaddingLen
	}
	if paddingLen >= 0 {
		opt.Option = append(opt.Option, &dnsmessage.EDNS0_PADDING{Padding: make([]byte, paddingLen)})
		payload, err = paddedQuery.Pack()
		if err != nil {
			return nil, nil, fmt.Errorf("pack padded DNS packet: %w", err)
		}
	}
	if err := netutils.CheckDnsMessageSize(len(payload)); err != nil {
		return nil, nil, err
	}
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	return paddedQuery, frame, nil
}

func resolveDoQ(stream doqStream, msg *dnsmessage.Msg) error {
	query, frame, err := packDoqQuery(msg)
	if err != nil {
		stream.CancelWrite(doqRequestCancelled)
		return err
	}
	return resolvePreparedDoQ(stream, msg, query, frame)
}

func resolvePreparedDoQ(stream doqStream, msg, query *dnsmessage.Msg, frame []byte) error {
	n, err := stream.Write(frame)
	if err != nil || n != len(frame) {
		stream.CancelWrite(doqRequestCancelled)
		if err == nil {
			err = io.ErrShortWrite
		}
		if streamErr, ok := errors.AsType[*quic.StreamError](err); ok && streamErr.Remote {
			return newDoqProtocolError(err)
		}
		return fmt.Errorf("write DoQ query: %w", err)
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("finish DoQ query: %w", err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return newDoqProtocolError(fmt.Errorf("read DoQ response length: %w", err))
		}
		return fmt.Errorf("read DoQ response length: %w", err)
	}
	responsePayload := make([]byte, int(binary.BigEndian.Uint16(lenBuf[:])))
	if _, err := io.ReadFull(stream, responsePayload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return newDoqProtocolError(fmt.Errorf("read DoQ response: %w", err))
		}
		return fmt.Errorf("read DoQ response: %w", err)
	}
	var response dnsmessage.Msg
	if err := netutils.UnpackDnsMessage(responsePayload, &response); err != nil {
		return newDoqProtocolError(fmt.Errorf("unpack DoQ response: %w", err))
	}
	if err := validateDoqOptions(&response); err != nil {
		return newDoqProtocolError(err)
	}
	if hasDnsTransactionSignature(&response) {
		return errors.New("DoQ forwarder cannot verify transaction signatures")
	}
	if err := netutils.ValidateDnsResponseAllowEmptyQuestion(query, &response, 0); err != nil {
		return newDoqProtocolError(err)
	}

	var trailing [1]byte
	for {
		n, err := stream.Read(trailing[:])
		if n != 0 {
			return newDoqProtocolError(errors.New("trailing data after DoQ response"))
		}
		if errors.Is(err, io.EOF) {
			*msg = response
			return nil
		}
		if err != nil {
			// A timeout or transport error cannot establish a framing violation.
			// Preserve it without terminating unrelated queries on this connection.
			return fmt.Errorf("wait for DoQ response FIN: %w", err)
		}
	}
}

func exchangeQUIC(ctx context.Context, dialer netproxy.Dialer, target netip.AddrPort, upstream *dns.Upstream, msg *dnsmessage.Msg) error {
	query, frame, err := packDoqQuery(msg)
	if err != nil {
		return err
	}
	conn, err := dialQUIC(ctx, dialer, target, &tls.Config{ServerName: upstream.Hostname, NextProtos: []string{"doq"}}, &quic.Config{
		MaxIncomingStreams: -1, MaxIncomingUniStreams: -1,
	})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(doqNoError, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.CancelRead(doqRequestCancelled)
	deadline, _ := ctx.Deadline()
	if err := stream.SetDeadline(deadline); err != nil {
		stream.CancelWrite(doqRequestCancelled)
		return err
	}
	stopDeadline := context.AfterFunc(ctx, func() { _ = stream.SetDeadline(time.Now()) })
	defer stopDeadline()
	err = resolvePreparedDoQ(stream, msg, query, frame)
	if _, ok := errors.AsType[*doqProtocolErrorCause](err); ok {
		_ = conn.CloseWithError(doqProtocolError, "DoQ protocol error")
	}
	return err
}

// The socket follows its QUIC connection, including failed handshakes and
// HTTP/3 transport retries. No forwarder-wide packet set or dial state is needed.
func dialQUIC(ctx context.Context, dialer netproxy.Dialer, target netip.AddrPort, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
	packet, err := dialer.ListenPacket(ctx, target.String())
	if err != nil {
		return nil, err
	}
	closePacket := sync.OnceFunc(func() { _ = packet.Close() })
	stop := context.AfterFunc(ctx, closePacket)
	conn, err := quic.DialEarly(ctx, packet, net.UDPAddrFromAddrPort(target), tlsConfig, config)
	stop()
	if err != nil {
		go closePacket()
		return nil, err
	}
	go func() { <-conn.Context().Done(); closePacket() }()
	return conn, nil
}
