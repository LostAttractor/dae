/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	dnsmessage "github.com/miekg/dns"
)

// TODO: Connection reuse
type DnsForwarder interface {
	ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error
	io.Closer
}

const (
	doqNoError          quic.ApplicationErrorCode = 0x0
	doqProtocolError    quic.ApplicationErrorCode = 0x2
	doqRequestCancelled quic.StreamErrorCode      = 0x3

	maxConcurrentDnsUDPExchanges = 256
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

func hasDnsTransactionSignature(msg *dnsmessage.Msg) bool {
	for _, rr := range msg.Extra {
		if rr != nil && (rr.Header().Rrtype == dnsmessage.TypeTSIG || rr.Header().Rrtype == dnsmessage.TypeSIG) {
			return true
		}
	}
	return false
}

func validateDNSForwardQuery(msg *dnsmessage.Msg, transport string, rejectZoneTransfer bool) error {
	for _, question := range msg.Question {
		if rejectZoneTransfer && (question.Qtype == dnsmessage.TypeAXFR || question.Qtype == dnsmessage.TypeIXFR) {
			return fmt.Errorf("%s zone transfers are not supported", transport)
		}
	}
	if hasDnsTransactionSignature(msg) {
		return fmt.Errorf("%s forwarder does not support transaction signatures", transport)
	}
	return nil
}

func dnsForwarderOperationError(callerCtx context.Context, state *dnsForwarderState, operationCtx context.Context, operationErr error) error {
	if callerCtx != nil {
		if err := callerCtx.Err(); err != nil {
			return err
		}
	}
	if state.isClosed() {
		return net.ErrClosed
	}
	if err := state.context().Err(); err != nil {
		return err
	}
	if operationCtx != nil {
		if err := operationCtx.Err(); err != nil {
			return err
		}
	}
	return operationErr
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

func closeAsync(closer io.Closer) {
	if closer != nil {
		go func() { _ = closer.Close() }()
	}
}

type dnsForwarderState struct {
	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool
}

func newDNSForwarderState(parent context.Context) *dnsForwarderState {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &dnsForwarderState{ctx: ctx, cancel: cancel}
}

func (s *dnsForwarderState) isClosed() bool {
	return s != nil && s.closed.Load()
}

func (s *dnsForwarderState) context() context.Context {
	if s == nil || s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

func (s *dnsForwarderState) close() bool {
	if s == nil {
		return true
	}
	if !s.closed.CompareAndSwap(false, true) {
		return false
	}
	if s.cancel != nil {
		s.cancel()
	}
	return true
}

func (s *dnsForwarderState) deriveContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	derived, cancel := context.WithCancel(ctx)
	if s.context().Err() != nil {
		cancel()
		return derived, cancel
	}
	stop := context.AfterFunc(s.context(), cancel)
	return derived, func() {
		stop()
		cancel()
	}
}

func newDnsForwarder(parent context.Context, upstream *dns.Upstream, dialArgument dialArgument) (DnsForwarder, error) {
	state := newDNSForwarderState(parent)
	forwarder, err := func() (DnsForwarder, error) {
		switch dialArgument.networkType.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_TCP, dns.UpstreamScheme_TCP_UDP:
				return &DoTCP{Upstream: *upstream, dialArgument: dialArgument, state: state}, nil
			case dns.UpstreamScheme_TLS:
				return &DoTLS{
					Upstream: *upstream, dialArgument: dialArgument, state: state,
				}, nil
			case dns.UpstreamScheme_HTTPS:
				return &DoH{Upstream: *upstream, dialArgument: dialArgument, http3: false, state: state}, nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		case consts.L4ProtoStr_UDP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_UDP, dns.UpstreamScheme_TCP_UDP:
				return &DoUDP{Upstream: *upstream, dialArgument: dialArgument, state: state}, nil
			case dns.UpstreamScheme_QUIC:
				return &DoQ{Upstream: *upstream, dialArgument: dialArgument, state: state}, nil
			case dns.UpstreamScheme_H3:
				return &DoH{Upstream: *upstream, dialArgument: dialArgument, http3: true, state: state}, nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		default:
			return nil, fmt.Errorf("unexpected l4proto: %v", dialArgument.networkType.L4Proto)
		}
	}()
	if err != nil {
		state.close()
		return nil, err
	}
	return forwarder, nil
}

type DoH struct {
	dns.Upstream
	dialArgument dialArgument
	http3        bool
	state        *dnsForwarderState

	mu          sync.Mutex
	client      *http.Client
	rt          http.RoundTripper
	packetConns map[net.PacketConn]struct{}
}

// getClient lazily builds and caches one HTTP client per forwarder so
// connections (TCP+TLS for DoH, QUIC for DoH3) are reused across queries.
func (d *DoH) getClient() (*http.Client, error) {
	if d.state.isClosed() {
		return nil, net.ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.isClosed() {
		return nil, net.ErrClosed
	}
	if d.client != nil {
		return d.client, nil
	}
	var roundTripper http.RoundTripper
	if d.http3 {
		roundTripper = d.getHttp3RoundTripper()
	} else {
		roundTripper = d.getHttpRoundTripper()
	}
	d.rt = roundTripper
	d.client = &http.Client{
		Transport: roundTripper,
		Timeout:   consts.DefaultDNSTimeout,
		// disable redirect https://github.com/daeuniverse/dae/pull/649#issuecomment-2379577896
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("do not use a server that will redirect, url: %v", d.Upstream.String())
		},
	}
	return d.client, nil
}

// Close releases the cached client, its idle connections and, for DoH3, the
// underlying QUIC packet sockets.
func (d *DoH) Close() error {
	if !d.state.close() {
		return nil
	}
	d.mu.Lock()
	client := d.client
	roundTripper := d.rt
	packetConns := make([]net.PacketConn, 0, len(d.packetConns))
	for conn := range d.packetConns {
		packetConns = append(packetConns, conn)
	}
	d.client = nil
	d.rt = nil
	d.packetConns = nil
	d.mu.Unlock()

	if client != nil {
		client.CloseIdleConnections()
	}
	var err error
	for _, conn := range packetConns {
		if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, closeErr)
		}
	}
	if closer, ok := roundTripper.(io.Closer); ok {
		if closeErr := closer.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, closeErr)
		}
	}
	return err
}

func (d *DoH) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	if err := validateDNSForwardQuery(msg, "DoH", false); err != nil {
		return err
	}
	parentCtx := ctx
	client, err := d.getClient()
	if err != nil {
		return err
	}
	ctx, cancel := d.state.deriveContext(ctx)
	defer cancel()
	response := msg.Copy()
	if err := netutils.ResolveHttp(ctx, client, &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(d.Upstream.Hostname, fmt.Sprint(d.Upstream.Port)),
		Path:   d.Upstream.Path,
	}, response); err != nil {
		if parentCtx != nil && parentCtx.Err() != nil {
			return parentCtx.Err()
		}
		if d.state.isClosed() {
			return net.ErrClosed
		}
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	*msg = *response
	return nil
}

func (d *DoH) getHttpRoundTripper() *http.Transport {
	httpTransport := http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         d.Upstream.Hostname,
			InsecureSkipVerify: false,
		},
		// A custom DialContext disables automatic HTTP/2; opt back in so
		// DoH queries multiplex on one connection.
		ForceAttemptHTTP2: true,
		IdleConnTimeout:   90 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ctx, cancel := d.state.deriveContext(ctx)
			defer cancel()
			return d.dialArgument.Dialer.DialContext(ctx, "tcp", d.dialArgument.Target.String())
		},
	}

	return &httpTransport
}

func (d *DoH) getHttp3RoundTripper() *http3.RoundTripper {
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			ServerName:         d.Upstream.Hostname,
			NextProtos:         []string{"h3"},
			InsecureSkipVerify: false,
		},
		QUICConfig: &quic.Config{},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			ctx, cancel := d.state.deriveContext(ctx)
			defer cancel()
			udpAddr := net.UDPAddrFromAddrPort(d.dialArgument.Target)
			packetConn, err := d.dialArgument.Dialer.ListenPacket(ctx, d.dialArgument.Target.String())
			if err != nil {
				return nil, err
			}
			d.mu.Lock()
			if d.state.isClosed() {
				d.mu.Unlock()
				closeAsync(packetConn)
				return nil, net.ErrClosed
			}
			if d.packetConns == nil {
				d.packetConns = make(map[net.PacketConn]struct{})
			}
			d.packetConns[packetConn] = struct{}{}
			d.mu.Unlock()
			stopClose := context.AfterFunc(ctx, func() { closeAsync(packetConn) })
			connection, err := quic.DialEarly(ctx, packetConn, udpAddr, tlsCfg, cfg)
			if !stopClose() {
				d.mu.Lock()
				delete(d.packetConns, packetConn)
				d.mu.Unlock()
				if connection != nil {
					_ = connection.CloseWithError(doqNoError, "")
				}
				closeAsync(packetConn)
				if ctxErr := ctx.Err(); ctxErr != nil {
					return nil, ctxErr
				}
				return nil, context.Canceled
			}
			if err != nil {
				d.mu.Lock()
				delete(d.packetConns, packetConn)
				d.mu.Unlock()
				closeAsync(packetConn)
				return nil, err
			}
			d.mu.Lock()
			if d.state.isClosed() {
				d.mu.Unlock()
				_ = connection.CloseWithError(doqNoError, "")
				closeAsync(packetConn)
				return nil, net.ErrClosed
			}
			d.mu.Unlock()
			go func() {
				<-connection.Context().Done()
				d.mu.Lock()
				delete(d.packetConns, packetConn)
				d.mu.Unlock()
				closeAsync(packetConn)
			}()
			return connection, nil
		},
	}
	return roundTripper
}

type DoQ struct {
	dns.Upstream
	dialArgument dialArgument
	state        *dnsForwarderState
	mu           sync.Mutex
	conn         quic.Connection
	packetConn   net.PacketConn
	dial         *doqDialState
}

type doqDialState struct {
	done       chan struct{}
	cancel     context.CancelFunc
	conn       quic.Connection
	packetConn net.PacketConn
	err        error
}

// getConn lazily dials the shared QUIC connection. One shared dial runs outside
// mu so Close can cancel it without allowing concurrent requests to accumulate
// blocked dials or packet sockets.
func (d *DoQ) getConn(requestCtx context.Context) (quic.Connection, error) {
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
	closeAsync(stalePacket)
	go d.runDial(dial)
	return d.waitForDial(requestCtx, dial)
}

func (d *DoQ) waitForDial(requestCtx context.Context, dial *doqDialState) (quic.Connection, error) {
	ctx, cancelState := d.state.deriveContext(requestCtx)
	defer cancelState()
	select {
	case <-dial.done:
		return dial.conn, dial.err
	case <-ctx.Done():
		if d.state.isClosed() {
			return nil, net.ErrClosed
		}
		if requestCtx != nil && requestCtx.Err() != nil {
			return nil, requestCtx.Err()
		}
		return nil, ctx.Err()
	}
}

func (d *DoQ) runDial(dial *doqDialState) {
	ctx, cancel := context.WithTimeout(d.state.context(), consts.DefaultDialTimeout)
	d.mu.Lock()
	dial.cancel = cancel
	d.mu.Unlock()
	conn, packetConn, err := d.createConnection(ctx, dial)
	cancel()

	var closeConn quic.Connection
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
		go func(connection quic.Connection, packet net.PacketConn) {
			<-connection.Context().Done()
			d.mu.Lock()
			if d.conn == connection {
				d.conn = nil
				d.packetConn = nil
			}
			d.mu.Unlock()
			closeAsync(packet)
		}(conn, packetConn)
	}
	d.mu.Lock()
	if d.dial == dial {
		d.dial = nil
	}
	close(dial.done)
	d.mu.Unlock()
}

func (d *DoQ) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
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
		if parentCtx != nil && parentCtx.Err() != nil {
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
	if err != nil && parentCtx != nil && parentCtx.Err() != nil {
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

func (d *DoQ) detachConnection(conn quic.Connection, code quic.ApplicationErrorCode, reason string) {
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

func (d *DoQ) Close() error {
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
		closeAsync(dialPacket)
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

func (d *DoQ) createConnection(ctx context.Context, dial *doqDialState) (quic.EarlyConnection, net.PacketConn, error) {
	packetConn, err := d.dialArgument.Dialer.ListenPacket(ctx, d.dialArgument.Target.String())
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

type dnsTLSExchange struct {
	conn      net.Conn
	closeOnce sync.Once
}

func (e *dnsTLSExchange) close() {
	e.closeOnce.Do(func() { _ = e.conn.Close() })
}

type DoTLS struct {
	dns.Upstream
	dialArgument dialArgument
	state        *dnsForwarderState
	mu           sync.Mutex
	exchanges    map[*dnsTLSExchange]struct{}
	workers      sync.WaitGroup
}

func (d *DoTLS) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	if err := validateDNSForwardQuery(msg, "DoT", true); err != nil {
		return err
	}
	d.mu.Lock()
	if d.state.isClosed() {
		d.mu.Unlock()
		return net.ErrClosed
	}
	d.workers.Add(1)
	d.mu.Unlock()
	workerStarted := false
	defer func() {
		if !workerStarted {
			d.workers.Done()
		}
	}()

	forwardCtx, cancelState := d.state.deriveContext(ctx)
	defer cancelState()
	dialCtx, cancelDial := context.WithTimeout(forwardCtx, consts.DefaultDialTimeout)
	conn, err := d.dialArgument.Dialer.DialContext(dialCtx, "tcp", d.dialArgument.Target.String())
	if err != nil {
		err = dnsForwarderOperationError(ctx, d.state, dialCtx, err)
	} else {
		err = dnsForwarderOperationError(ctx, d.state, forwardCtx, nil)
	}
	cancelDial()
	if err != nil {
		if conn != nil {
			workerStarted = true
			go func() {
				defer d.workers.Done()
				_ = conn.Close()
			}()
		}
		return err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	})
	exchange := &dnsTLSExchange{conn: conn}
	d.mu.Lock()
	if d.state.isClosed() {
		d.mu.Unlock()
		workerStarted = true
		go func() {
			defer d.workers.Done()
			_ = conn.Close()
		}()
		return net.ErrClosed
	}
	if d.exchanges == nil {
		d.exchanges = make(map[*dnsTLSExchange]struct{})
	}
	d.exchanges[exchange] = struct{}{}
	d.mu.Unlock()

	exchangeCtx, exchangeCancel := context.WithTimeout(forwardCtx, consts.DefaultDNSTimeout)
	defer exchangeCancel()
	request := msg.Copy()
	result := make(chan error, 1)
	workerStarted = true
	go func() {
		defer d.workers.Done()
		defer func() {
			d.mu.Lock()
			delete(d.exchanges, exchange)
			d.mu.Unlock()
		}()
		defer exchange.close()
		deadline, _ := exchangeCtx.Deadline()
		err := tlsConn.SetDeadline(deadline)
		if err == nil {
			stopContextClose := context.AfterFunc(exchangeCtx, exchange.close)
			err = tlsConn.HandshakeContext(exchangeCtx)
			if err == nil {
				err = netutils.ResolveStream(tlsConn, request)
			}
			stopContextClose()
		}
		result <- err
	}()

	select {
	case err = <-result:
		if err := dnsForwarderOperationError(ctx, d.state, exchangeCtx, err); err != nil {
			return err
		}
		*msg = *request
		return nil
	case <-exchangeCtx.Done():
		go exchange.close()
		return dnsForwarderOperationError(ctx, d.state, exchangeCtx, exchangeCtx.Err())
	}
}

func (d *DoTLS) Close() error {
	if !d.state.close() {
		return nil
	}
	d.mu.Lock()
	exchanges := make([]*dnsTLSExchange, 0, len(d.exchanges))
	for exchange := range d.exchanges {
		exchanges = append(exchanges, exchange)
	}
	d.mu.Unlock()
	for _, exchange := range exchanges {
		go exchange.close()
	}
	done := make(chan struct{})
	go func() {
		d.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(consts.DefaultDialTimeout):
		return fmt.Errorf("DoT exchange shutdown timeout: %w", context.DeadlineExceeded)
	}
}

// DoTCP is the persistent TCP forwarder. UDP deliberately uses
// DoUDP so concurrent exchanges cannot share a source port.
type DoTCP struct {
	dns.Upstream
	dialArgument dialArgument
	state        *dnsForwarderState
	mu           sync.Mutex
	dnsManager   *DnsManager
	retiring     *DnsManager
	closeErr     error
}

func (d *DoTCP) Close() error {
	if !d.state.close() {
		return nil
	}
	d.mu.Lock()
	manager, retiring, priorErr := d.dnsManager, d.retiring, d.closeErr
	d.dnsManager = nil
	d.retiring = nil
	d.closeErr = nil
	d.mu.Unlock()
	err := priorErr
	if manager != nil {
		manager.startClose()
	}
	if retiring != nil && retiring != manager {
		retiring.startClose()
	}
	ctx, cancel := context.WithTimeout(context.Background(), consts.DefaultDialTimeout)
	defer cancel()
	if manager != nil {
		err = errors.Join(err, manager.waitClosed(ctx))
	}
	if retiring != nil && retiring != manager {
		err = errors.Join(err, retiring.waitClosed(ctx))
	}
	return err
}

func (d *DoTCP) clearRetiringLocked() bool {
	if d.retiring == nil {
		return true
	}
	if !d.retiring.closeComplete() {
		return false
	}
	d.closeErr = errors.Join(d.closeErr, d.retiring.closeErr)
	d.retiring = nil
	return true
}

func (d *DoTCP) allowIdleClose(manager *DnsManager) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.isClosed() || d.dnsManager != manager {
		return true
	}
	return d.clearRetiringLocked()
}

func (d *DoTCP) getManager(ctx context.Context) (*DnsManager, error) {
	if d.state.isClosed() {
		return nil, net.ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state.isClosed() {
		return nil, net.ErrClosed
	}
	if d.dnsManager == nil || d.dnsManager.IsClosed() {
		if d.dnsManager != nil && !d.dnsManager.canReplace() {
			return nil, net.ErrClosed
		}
		if !d.clearRetiringLocked() {
			return nil, net.ErrClosed
		}
		previous := d.dnsManager
		dialCtx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
		defer cancel()
		conn, err := d.dialArgument.Dialer.DialContext(dialCtx, "tcp", d.dialArgument.Target.String())
		if err != nil {
			return nil, err
		}
		if d.state.isClosed() {
			closeAsync(conn)
			return nil, net.ErrClosed
		}
		var manager *DnsManager
		manager = newDnsManagerWithIdlePolicy(
			conn,
			consts.DefaultDNSTimeout,
			2*consts.DefaultDNSTimeout,
			func() bool { return d.allowIdleClose(manager) },
		)
		if previous != nil {
			if previous.closeComplete() {
				d.closeErr = errors.Join(d.closeErr, previous.closeErr)
			} else {
				d.retiring = previous
			}
		}
		d.dnsManager = manager
	}
	return d.dnsManager, nil
}

func (d *DoTCP) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	if err := validateDNSForwardQuery(msg, "TCP", true); err != nil {
		return err
	}
	parentCtx := ctx
	ctx, cancelState := d.state.deriveContext(ctx)
	defer cancelState()
	ctx, cancelTimeout := context.WithTimeout(ctx, consts.DefaultDNSTimeout)
	defer cancelTimeout()
	var lastErr error
	for attempts := 0; attempts < 2; attempts++ {
		manager, err := d.getManager(ctx)
		if err != nil {
			if parentCtx != nil && parentCtx.Err() != nil {
				return parentCtx.Err()
			}
			if d.state.isClosed() {
				return net.ErrClosed
			}
			return err
		}
		response := msg.Copy()
		err = manager.ResolveContext(ctx, response)
		lastErr = err
		if !shouldRetryDnsManager(err, msg) || ctx.Err() != nil {
			if err != nil && parentCtx != nil && parentCtx.Err() != nil {
				return parentCtx.Err()
			}
			if err != nil && d.state.isClosed() {
				return net.ErrClosed
			}
			if err == nil {
				if err := ctx.Err(); err != nil {
					return err
				}
				*msg = *response
			}
			return err
		}
	}
	return lastErr
}

func shouldRetryDnsManager(err error, msg *dnsmessage.Msg) bool {
	if errors.Is(err, errDnsManagerUnavailable) {
		return true
	}
	return msg.Opcode == dnsmessage.OpcodeQuery && errors.Is(err, errDnsExchangeInterrupted)
}

type DoUDP struct {
	dns.Upstream
	dialArgument    dialArgument
	state           *dnsForwarderState
	mu              sync.Mutex
	connections     map[net.Conn]struct{}
	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	slots           chan struct{}
	closeDone       chan struct{}
	closeErr        error
	active          sync.WaitGroup
	closed          bool
}

func (d *DoUDP) Close() error {
	d.state.close()
	d.mu.Lock()
	d.ensureLifecycleLocked()
	if d.closed {
		d.mu.Unlock()
		return d.waitForShutdown()
	}
	d.closed = true
	d.lifecycleCancel()
	connections := make([]net.Conn, 0, len(d.connections))
	for conn := range d.connections {
		connections = append(connections, conn)
	}
	d.connections = nil
	d.mu.Unlock()
	closeResults := make(chan error, len(connections))
	for _, conn := range connections {
		go func() { closeResults <- conn.Close() }()
	}
	go func() {
		var errs []error
		for range connections {
			if err := <-closeResults; err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
		d.active.Wait()
		d.closeErr = errors.Join(errs...)
		close(d.closeDone)
	}()
	return d.waitForShutdown()
}

func (d *DoUDP) waitForShutdown() error {
	select {
	case <-d.closeDone:
		return d.closeErr
	case <-time.After(consts.DefaultDialTimeout):
		return fmt.Errorf("UDP exchange shutdown timeout: %w", context.DeadlineExceeded)
	}
}

func (d *DoUDP) ensureLifecycleLocked() {
	if d.lifecycleCtx == nil {
		d.lifecycleCtx, d.lifecycleCancel = context.WithCancel(d.state.context())
		d.slots = make(chan struct{}, maxConcurrentDnsUDPExchanges)
		d.closeDone = make(chan struct{})
	}
}

func (d *DoUDP) beginExchange(ctx context.Context) (context.Context, context.CancelFunc, bool) {
	d.mu.Lock()
	d.ensureLifecycleLocked()
	if d.closed || d.state.isClosed() {
		d.mu.Unlock()
		return nil, nil, false
	}
	d.active.Add(1)
	lifecycleCtx := d.lifecycleCtx
	slots := d.slots
	d.mu.Unlock()

	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		d.active.Done()
		return nil, nil, false
	case <-lifecycleCtx.Done():
		d.active.Done()
		return nil, nil, false
	}

	exchangeCtx, cancel := context.WithCancel(ctx)
	stopLifecycleCancel := context.AfterFunc(lifecycleCtx, cancel)
	return exchangeCtx, func() {
		stopLifecycleCancel()
		cancel()
		<-slots
		d.active.Done()
	}, true
}

func (d *DoUDP) registerConnection(conn net.Conn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.state.isClosed() {
		return false
	}
	if d.connections == nil {
		d.connections = make(map[net.Conn]struct{})
	}
	d.connections[conn] = struct{}{}
	return true
}

func (d *DoUDP) releaseConnection(conn net.Conn) {
	go func() {
		_ = conn.Close()
		d.mu.Lock()
		delete(d.connections, conn)
		d.mu.Unlock()
	}()
}

func (d *DoUDP) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	if err := validateDNSForwardQuery(msg, "UDP", true); err != nil {
		return err
	}
	parentCtx := ctx
	ctx, cancelState := d.state.deriveContext(ctx)
	defer cancelState()
	ctx, cancelTimeout := context.WithTimeout(ctx, consts.DefaultDNSTimeout)
	defer cancelTimeout()
	exchangeCtx, endExchange, started := d.beginExchange(ctx)
	if !started {
		if parentCtx != nil && parentCtx.Err() != nil {
			return parentCtx.Err()
		}
		if d.state.isClosed() {
			return net.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return net.ErrClosed
	}
	defer endExchange()
	ctx = exchangeCtx
	conn, err := d.dialArgument.Dialer.DialContext(ctx, "udp", d.dialArgument.Target.String())
	if err != nil {
		if parentCtx != nil && parentCtx.Err() != nil {
			return parentCtx.Err()
		}
		if d.state.isClosed() {
			return net.ErrClosed
		}
		return err
	}
	if !d.registerConnection(conn) {
		closeAsync(conn)
		return net.ErrClosed
	}
	defer d.releaseConnection(conn)

	wireQuery := msg.Copy()
	var randomID [2]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return fmt.Errorf("generate DNS transaction ID: %w", err)
	}
	originalID := msg.Id
	wireQuery.Id = binary.BigEndian.Uint16(randomID[:])
	if err := netutils.ResolveUDP(ctx, conn, wireQuery); err != nil {
		if parentCtx != nil && parentCtx.Err() != nil {
			return parentCtx.Err()
		}
		if d.state.isClosed() {
			return net.ErrClosed
		}
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	*msg = *wireQuery
	msg.Id = originalID
	return nil
}
