/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
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
		var streamErr *quic.StreamError
		if errors.As(err, &streamErr) && streamErr.Remote {
			return newDoqProtocolError(err)
		}
		return fmt.Errorf("write DoQ query: %w", err)
	}
	if err := stream.Close(); err != nil {
		return newDoqProtocolError(fmt.Errorf("finish DoQ query: %w", err))
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
			var streamErr *quic.StreamError
			if errors.As(err, &streamErr) {
				return err
			}
			return newDoqProtocolError(fmt.Errorf("wait for DoQ response FIN: %w", err))
		}
	}
}

type quicDNSForwarder struct {
	dns.Upstream
	dialArgument dialArgument
	state        *dnsForwarderState
	mu           sync.Mutex
	conn         *quic.Conn
	packetConn   net.PacketConn
	dial         *doqDialState
}

type doqDialState struct {
	done       chan struct{}
	cancel     context.CancelFunc
	conn       *quic.Conn
	packetConn net.PacketConn
	err        error
}

// getConn lazily dials the shared QUIC connection. One shared dial runs outside
// mu so Close can cancel it without allowing concurrent requests to accumulate
// blocked dials or packet sockets.
func (d *quicDNSForwarder) getConn(requestCtx context.Context) (*quic.Conn, error) {
	if d.state.isClosed() {
		return nil, net.ErrClosed
	}
	d.mu.Lock()
	if d.state.isClosed() {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	if d.conn != nil && d.conn.Context().Err() == nil {
		conn := d.conn
		d.mu.Unlock()
		return conn, nil
	}
	if d.dial != nil {
		dial := d.dial
		d.mu.Unlock()
		return d.waitForDial(requestCtx, dial)
	}
	staleConn, stalePacket := d.conn, d.packetConn
	d.conn = nil
	d.packetConn = nil
	dial := &doqDialState{done: make(chan struct{})}
	d.dial = dial
	d.mu.Unlock()
	if staleConn != nil {
		_ = staleConn.CloseWithError(doqNoError, "")
	}
	closeInBackground(stalePacket)
	go d.runDial(dial)
	return d.waitForDial(requestCtx, dial)
}

func (d *quicDNSForwarder) waitForDial(requestCtx context.Context, dial *doqDialState) (*quic.Conn, error) {
	ctx, cancelState := d.state.deriveContext(requestCtx)
	defer cancelState()
	select {
	case <-dial.done:
		return dial.conn, dial.err
	case <-ctx.Done():
		if d.state.isClosed() {
			return nil, net.ErrClosed
		}
		if requestCtx.Err() != nil {
			return nil, requestCtx.Err()
		}
		return nil, ctx.Err()
	}
}

func (d *quicDNSForwarder) runDial(dial *doqDialState) {
	ctx, cancel := context.WithTimeout(d.state.ctx, consts.DefaultDialTimeout)
	d.mu.Lock()
	dial.cancel = cancel
	d.mu.Unlock()
	conn, packetConn, err := d.createConnection(ctx, dial)
	cancel()

	var closeConn *quic.Conn
	var closePacket net.PacketConn
	d.mu.Lock()
	if dial.packetConn == packetConn {
		dial.packetConn = nil
	}
	if err == nil && !d.state.isClosed() {
		d.conn = conn
		d.packetConn = packetConn
		dial.conn = conn
	} else {
		if d.state.isClosed() {
			err = net.ErrClosed
		}
		closeConn, closePacket = conn, packetConn
	}
	dial.err = err
	d.mu.Unlock()

	if closeConn != nil {
		_ = closeConn.CloseWithError(doqNoError, "")
	}
	if closePacket != nil {
		_ = closePacket.Close()
	}
	if err == nil {
		go func(connection *quic.Conn, packet net.PacketConn) {
			<-connection.Context().Done()
			d.mu.Lock()
			if d.conn == connection {
				d.conn = nil
				d.packetConn = nil
			}
			d.mu.Unlock()
			closeInBackground(packet)
		}(conn, packetConn)
	}
	d.mu.Lock()
	if d.dial == dial {
		d.dial = nil
	}
	close(dial.done)
	d.mu.Unlock()
}

func (d *quicDNSForwarder) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	originalID := msg.Id
	query, frame, err := packDoqQuery(msg)
	if err != nil {
		return err
	}
	conn, err := d.getConn(ctx)
	if err != nil {
		return err
	}

	parentCtx := ctx
	ctx, cancelState := d.state.deriveContext(ctx)
	defer cancelState()
	ctx, cancelTimeout := context.WithTimeout(ctx, consts.DefaultDNSTimeout)
	defer cancelTimeout()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		// A local stream-limit timeout doesn't make the shared connection bad.
		// Only discard it when quic-go has already closed the connection.
		if conn.Context().Err() != nil {
			d.detachConnection(conn, doqNoError, "")
		}
		if parentCtx.Err() != nil {
			return parentCtx.Err()
		}
		if d.state.isClosed() {
			return net.ErrClosed
		}
		return err
	}
	defer stream.CancelRead(doqRequestCancelled)
	deadline, _ := ctx.Deadline()
	if err := stream.SetDeadline(deadline); err != nil {
		stream.CancelWrite(doqRequestCancelled)
		return err
	}
	stopDeadline := context.AfterFunc(ctx, func() { _ = stream.SetDeadline(time.Now()) })
	response := msg.Copy()
	err = resolvePreparedDoQ(stream, response, query, frame)
	stopDeadline()
	if err != nil && parentCtx.Err() != nil {
		return parentCtx.Err()
	}
	if err != nil && d.state.isClosed() {
		return net.ErrClosed
	}
	var protocolErr *doqProtocolErrorCause
	if errors.As(err, &protocolErr) {
		d.detachConnection(conn, doqProtocolError, "DoQ protocol error")
		return err
	}
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	response.Id = originalID
	*msg = *response
	return nil
}

func (d *quicDNSForwarder) detachConnection(conn *quic.Conn, code quic.ApplicationErrorCode, reason string) {
	d.mu.Lock()
	if d.conn != conn {
		d.mu.Unlock()
		return
	}
	packetConn := d.packetConn
	d.conn = nil
	d.packetConn = nil
	d.mu.Unlock()
	go func() {
		_ = conn.CloseWithError(code, reason)
		if packetConn != nil {
			_ = packetConn.Close()
		}
	}()
}

func (d *quicDNSForwarder) Close() error {
	if !d.state.close() {
		return nil
	}
	d.mu.Lock()
	conn, packetConn := d.conn, d.packetConn
	dial := d.dial
	var dialPacket net.PacketConn
	var dialCancel context.CancelFunc
	if dial != nil {
		dialPacket = dial.packetConn
		dialCancel = dial.cancel
	}
	d.conn = nil
	d.packetConn = nil
	d.mu.Unlock()
	if dialCancel != nil {
		dialCancel()
	}
	var err error
	if conn != nil {
		if closeErr := conn.CloseWithError(doqNoError, ""); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			err = closeErr
		}
	}
	if packetConn != nil {
		if closeErr := packetConn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, closeErr)
		}
	}
	if dialPacket != nil && dialPacket != packetConn {
		closeInBackground(dialPacket)
	}
	if dial != nil {
		timer := time.NewTimer(consts.DefaultDialTimeout)
		defer timer.Stop()
		select {
		case <-dial.done:
		case <-timer.C:
			err = errors.Join(err, fmt.Errorf("DoQ dial shutdown timeout: %w", context.DeadlineExceeded))
		}
	}
	return err
}

func (d *quicDNSForwarder) createConnection(ctx context.Context, dial *doqDialState) (*quic.Conn, net.PacketConn, error) {
	packetConn, err := d.dialArgument.dialerForConnection().ListenPacket(ctx, d.dialArgument.Target.String())
	if err != nil {
		return nil, nil, err
	}
	d.mu.Lock()
	if d.state.isClosed() || d.dial != dial {
		d.mu.Unlock()
		return nil, packetConn, net.ErrClosed
	}
	dial.packetConn = packetConn
	d.mu.Unlock()
	contextCloseDone := make(chan error, 1)
	stopClose := context.AfterFunc(ctx, func() { contextCloseDone <- packetConn.Close() })

	tlsCfg := &tls.Config{
		NextProtos:         []string{"doq"},
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	}
	addr := net.UDPAddrFromAddrPort(d.dialArgument.Target)
	connection, err := quic.DialEarly(ctx, packetConn, addr, tlsCfg, &quic.Config{
		MaxIncomingStreams:    -1,
		MaxIncomingUniStreams: -1,
	})
	if !stopClose() {
		closeErr := <-contextCloseDone
		d.mu.Lock()
		if dial.packetConn == packetConn {
			dial.packetConn = nil
		}
		d.mu.Unlock()
		if connection != nil {
			_ = connection.CloseWithError(doqNoError, "")
		}
		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, closeErr)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, errors.Join(ctxErr, err)
		}
		return nil, nil, errors.Join(context.Canceled, err)
	}
	if err != nil {
		return nil, packetConn, err
	}
	return connection, packetConn, nil
}
