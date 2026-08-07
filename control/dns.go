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
	"net/http"
	"net/url"
	"sync"
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
}

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
	Context() context.Context
}

func newDoqProtocolError(err error) error {
	return &doqProtocolErrorCause{err: err}
}

func hasDoqTcpKeepalive(msg *dnsmessage.Msg) bool {
	opt := msg.IsEdns0()
	if opt == nil {
		return false
	}
	for _, option := range opt.Option {
		if _, ok := option.(*dnsmessage.EDNS0_TCP_KEEPALIVE); ok {
			return true
		}
	}
	return false
}

func packDoqQuery(msg *dnsmessage.Msg) (*dnsmessage.Msg, []byte, error) {
	if len(msg.Question) != 0 {
		switch msg.Question[0].Qtype {
		case dnsmessage.TypeAXFR, dnsmessage.TypeIXFR:
			return nil, nil, errors.New("DoQ zone transfers are not supported")
		}
	}
	if hasDoqTcpKeepalive(msg) {
		return nil, nil, errors.New("DoQ query contains EDNS TCP keepalive")
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
		if _, ok := option.(*dnsmessage.EDNS0_PADDING); !ok {
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
	if err := response.Unpack(responsePayload); err != nil {
		return newDoqProtocolError(fmt.Errorf("unpack DoQ response: %w", err))
	}
	if hasDoqTcpKeepalive(&response) {
		return newDoqProtocolError(errors.New("DoQ response contains EDNS TCP keepalive"))
	}
	if err := netutils.ValidateDnsResponse(query, &response, 0); err != nil {
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

// ownedPacketConnEarlyConnection closes the caller-created packet socket with
// the QUIC connection. quic.DialEarly deliberately leaves supplied sockets
// under caller ownership.
type ownedPacketConnEarlyConnection struct {
	quic.EarlyConnection
	packetConn net.PacketConn
	closeOnce  sync.Once
}

func ownPacketConn(conn quic.EarlyConnection, packetConn net.PacketConn) quic.EarlyConnection {
	owned := &ownedPacketConnEarlyConnection{
		EarlyConnection: conn,
		packetConn:      packetConn,
	}
	go func() {
		<-conn.Context().Done()
		owned.closePacketConn()
	}()
	return owned
}

func (c *ownedPacketConnEarlyConnection) closePacketConn() error {
	var err error
	c.closeOnce.Do(func() { err = c.packetConn.Close() })
	return err
}

func (c *ownedPacketConnEarlyConnection) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	return errors.Join(c.EarlyConnection.CloseWithError(code, reason), c.closePacketConn())
}

func newDnsForwarder(upstream *dns.Upstream, dialArgument dialArgument) (DnsForwarder, error) {
	forwarder, err := func() (DnsForwarder, error) {
		switch dialArgument.networkType.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_TCP, dns.UpstreamScheme_TCP_UDP:
				return &DoTCP{Upstream: *upstream, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_TLS:
				return &DoTLS{Upstream: *upstream, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_HTTPS:
				return &DoH{Upstream: *upstream, dialArgument: dialArgument, http3: false}, nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		case consts.L4ProtoStr_UDP:
			switch upstream.Scheme {
			case dns.UpstreamScheme_UDP, dns.UpstreamScheme_TCP_UDP:
				return &DoUDP{Upstream: *upstream, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_QUIC:
				return &DoQ{Upstream: *upstream, dialArgument: dialArgument}, nil
			case dns.UpstreamScheme_H3:
				return &DoH{Upstream: *upstream, dialArgument: dialArgument, http3: true}, nil
			default:
				return nil, fmt.Errorf("unexpected scheme: %v", upstream.Scheme)
			}
		default:
			return nil, fmt.Errorf("unexpected l4proto: %v", dialArgument.networkType.L4Proto)
		}
	}()
	if err != nil {
		return nil, err
	}
	return forwarder, nil
}

type DoH struct {
	dns.Upstream
	dialArgument dialArgument
	http3        bool

	mu     sync.Mutex
	client *http.Client
	rt     http.RoundTripper
}

// getClient lazily builds and caches one HTTP client per forwarder so
// connections (TCP+TLS for DoH, QUIC for DoH3) are reused across queries
// instead of leaking a transport, its goroutines and its idle connections
// on every lookup.
func (d *DoH) getClient() *http.Client {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.client != nil {
		return d.client
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
	return d.client
}

// Close releases the cached client, its idle connections and, for DoH3, the
// underlying QUIC connection.
func (d *DoH) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var err error
	if closer, ok := d.rt.(io.Closer); ok {
		err = closer.Close()
	} else if d.client != nil {
		d.client.CloseIdleConnections()
	}
	d.client = nil
	d.rt = nil
	return err
}

func (d *DoH) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	serverURL := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(d.Upstream.Hostname, fmt.Sprint(d.Upstream.Port)),
		Path:   d.Upstream.Path,
	}

	return netutils.ResolveHttp(ctx, d.getClient(), serverURL, msg)
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
			conn, err := d.dialArgument.Dialer.DialContext(ctx, "tcp", d.dialArgument.Target.String())
			if err != nil {
				return nil, err
			}
			return conn, nil
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
			udpAddr := net.UDPAddrFromAddrPort(d.dialArgument.Target)
			packetConn, err := d.dialArgument.Dialer.ListenPacket(ctx, d.dialArgument.Target.String())
			if err != nil {
				return nil, err
			}
			conn, err := quic.DialEarly(ctx, packetConn, udpAddr, tlsCfg, cfg)
			if err != nil {
				_ = packetConn.Close()
				return nil, err
			}
			return ownPacketConn(conn, packetConn), nil
		},
	}
	return roundTripper
}

type DoQ struct {
	dns.Upstream
	dialArgument dialArgument
	mu           sync.Mutex
	conn         quic.Connection
}

// getConn lazily dials the shared QUIC connection. The mutex keeps
// concurrent first queries from each creating a connection and leaking all
// but one.
func (d *DoQ) getConn(ctx context.Context) (quic.Connection, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn == nil || d.conn.Context().Err() != nil {
		ctx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
		defer cancel()
		conn, err := d.createConnection(ctx)
		if err != nil {
			return nil, err
		}
		d.conn = conn
	}
	return d.conn, nil
}

func (d *DoQ) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	if _, _, err := packDoqQuery(msg); err != nil {
		return err
	}
	conn, err := d.getConn(ctx)
	if err != nil {
		return err
	}

	parentCtx := ctx
	ctx, cancel := context.WithTimeout(ctx, consts.DefaultDNSTimeout)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		// A local stream-limit timeout doesn't make the shared connection bad.
		// Only discard it when quic-go has already closed the connection.
		if conn.Context().Err() != nil {
			d.mu.Lock()
			if d.conn == conn {
				d.conn = nil
			}
			d.mu.Unlock()
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
	err = resolveDoQ(stream, msg)
	stopDeadline()
	if err != nil && parentCtx.Err() != nil {
		return parentCtx.Err()
	}
	var protocolErr *doqProtocolErrorCause
	if errors.As(err, &protocolErr) {
		d.closeConnection(conn, doqProtocolError, "DoQ protocol error")
		return err
	}
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (d *DoQ) closeConnection(conn quic.Connection, code quic.ApplicationErrorCode, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn == conn {
		_ = d.conn.CloseWithError(code, reason)
		d.conn = nil
	}
}

func (d *DoQ) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		err := d.conn.CloseWithError(doqNoError, "")
		d.conn = nil
		return err
	}
	return nil
}

func (d *DoQ) createConnection(ctx context.Context) (quic.EarlyConnection, error) {
	packetConn, err := d.dialArgument.Dialer.ListenPacket(ctx, d.dialArgument.Target.String())
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		NextProtos:         []string{"doq"},
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	}
	addr := net.UDPAddrFromAddrPort(d.dialArgument.Target)
	conn, err := quic.DialEarly(ctx, packetConn, addr, tlsCfg, &quic.Config{
		MaxIncomingStreams:    -1,
		MaxIncomingUniStreams: -1,
	})
	if err != nil {
		_ = packetConn.Close()
		return nil, err
	}
	return ownPacketConn(conn, packetConn), nil
}

type DoTLS struct {
	dns.Upstream
	dialArgument dialArgument
}

func (d *DoTLS) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	dialCtx, cancelDial := context.WithTimeout(ctx, consts.DefaultDialTimeout)
	conn, err := d.dialArgument.Dialer.DialContext(dialCtx, "tcp", d.dialArgument.Target.String())
	cancelDial()
	if err != nil {
		return err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         d.Upstream.Hostname,
	})
	defer tlsConn.Close()
	queryCtx, cancelQuery := context.WithTimeout(ctx, consts.DefaultDNSTimeout)
	defer cancelQuery()
	stopClose := context.AfterFunc(queryCtx, func() { _ = tlsConn.Close() })
	defer stopClose()
	if err = tlsConn.HandshakeContext(queryCtx); err != nil {
		if queryCtx.Err() != nil {
			return queryCtx.Err()
		}
		return err
	}
	err = netutils.ResolveStream(tlsConn, msg)
	if err != nil && queryCtx.Err() != nil {
		return queryCtx.Err()
	}
	return err
}

type DoTCP struct {
	dns.Upstream
	dialArgument dialArgument
	mu           sync.Mutex
	dnsManager   *DnsManager
	dnsManagers  map[*DnsManager]struct{}
	closed       bool
}

// Close releases the persistent upstream connection, if any, so its socket
// and the DnsManager recv loop do not outlive the owning control plane.
func (d *DoTCP) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	var errs []error
	for manager := range d.dnsManagers {
		errs = append(errs, manager.Close())
	}
	return errors.Join(errs...)
}

// getManager lazily dials the shared upstream connection. The mutex keeps
// concurrent first queries from each creating a DnsManager and leaking all
// but one (socket and recv goroutine included).
func (d *DoTCP) getManager(ctx context.Context) (*DnsManager, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, net.ErrClosed
	}
	if d.dnsManager == nil || d.dnsManager.IsClosed() {
		ctx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
		defer cancel()
		conn, err := d.dialArgument.Dialer.DialContext(ctx, "tcp", d.dialArgument.Target.String())
		if err != nil {
			return nil, err
		}
		manager := NewDnsManager(conn, true)
		d.dnsManager = manager
		if d.dnsManagers == nil {
			d.dnsManagers = make(map[*DnsManager]struct{})
		}
		d.dnsManagers[manager] = struct{}{}
		go func() {
			<-manager.closeDone
			d.mu.Lock()
			delete(d.dnsManagers, manager)
			d.mu.Unlock()
		}()
	}
	return d.dnsManager, nil
}

func (d *DoTCP) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	for attempts := 0; attempts < 2; attempts++ {
		m, err := d.getManager(ctx)
		if err != nil {
			return err
		}
		err = m.ResolveContext(ctx, msg)
		if !errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
			return err
		}
	}
	return net.ErrClosed
}

type DoUDP struct {
	dns.Upstream
	dialArgument dialArgument
	mu           sync.Mutex
	dnsManager   *DnsManager
	dnsManagers  map[*DnsManager]struct{}
	closed       bool
}

// Close releases the persistent upstream connection, if any, so its socket
// and the DnsManager recv loop do not outlive the owning control plane.
func (d *DoUDP) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	var errs []error
	for manager := range d.dnsManagers {
		errs = append(errs, manager.Close())
	}
	return errors.Join(errs...)
}

// See DoTCP.getManager.
func (d *DoUDP) getManager(ctx context.Context) (*DnsManager, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, net.ErrClosed
	}
	if d.dnsManager == nil || d.dnsManager.IsClosed() {
		ctx, cancel := context.WithTimeout(ctx, consts.DefaultDialTimeout)
		defer cancel()
		conn, err := d.dialArgument.Dialer.DialContext(ctx, "udp", d.dialArgument.Target.String())
		if err != nil {
			return nil, err
		}
		manager := NewDnsManager(conn, false)
		d.dnsManager = manager
		if d.dnsManagers == nil {
			d.dnsManagers = make(map[*DnsManager]struct{})
		}
		dnsManagers := d.dnsManagers
		dnsManagers[manager] = struct{}{}
		go func() {
			<-manager.closeDone
			d.mu.Lock()
			delete(dnsManagers, manager)
			d.mu.Unlock()
		}()
	}
	return d.dnsManager, nil
}

func (d *DoUDP) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
	for attempts := 0; attempts < 2; attempts++ {
		m, err := d.getManager(ctx)
		if err != nil {
			return err
		}
		err = m.ResolveContext(ctx, msg)
		if !errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
			return err
		}
	}
	return net.ErrClosed
}
