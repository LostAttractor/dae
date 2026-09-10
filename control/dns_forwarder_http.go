/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"crypto/tls"
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

type httpDNSForwarder struct {
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
func (d *httpDNSForwarder) getClient() (*http.Client, error) {
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
func (d *httpDNSForwarder) Close() error {
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

func (d *httpDNSForwarder) ForwardDNS(ctx context.Context, msg *dnsmessage.Msg) error {
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
		if parentCtx.Err() != nil {
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

func (d *httpDNSForwarder) getHttpRoundTripper() *http.Transport {
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
			return d.dialArgument.dialerForConnection().DialContext(ctx, "tcp", d.dialArgument.Target.String())
		},
	}

	return &httpTransport
}

func (d *httpDNSForwarder) getHttp3RoundTripper() *http3.Transport {
	roundTripper := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         d.Upstream.Hostname,
			NextProtos:         []string{"h3"},
			InsecureSkipVerify: false,
		},
		QUICConfig: &quic.Config{},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			ctx, cancel := d.state.deriveContext(ctx)
			defer cancel()
			udpAddr := net.UDPAddrFromAddrPort(d.dialArgument.Target)
			packetConn, err := d.dialArgument.dialerForConnection().ListenPacket(ctx, d.dialArgument.Target.String())
			if err != nil {
				return nil, err
			}
			d.mu.Lock()
			if d.state.isClosed() {
				d.mu.Unlock()
				closeInBackground(packetConn)
				return nil, net.ErrClosed
			}
			if d.packetConns == nil {
				d.packetConns = make(map[net.PacketConn]struct{})
			}
			d.packetConns[packetConn] = struct{}{}
			d.mu.Unlock()
			stopClose := context.AfterFunc(ctx, func() { closeInBackground(packetConn) })
			connection, err := quic.DialEarly(ctx, packetConn, udpAddr, tlsCfg, cfg)
			if !stopClose() {
				d.mu.Lock()
				delete(d.packetConns, packetConn)
				d.mu.Unlock()
				if connection != nil {
					_ = connection.CloseWithError(doqNoError, "")
				}
				closeInBackground(packetConn)
				if ctxErr := ctx.Err(); ctxErr != nil {
					return nil, ctxErr
				}
				return nil, context.Canceled
			}
			if err != nil {
				d.mu.Lock()
				delete(d.packetConns, packetConn)
				d.mu.Unlock()
				closeInBackground(packetConn)
				return nil, err
			}
			d.mu.Lock()
			if d.state.isClosed() {
				d.mu.Unlock()
				_ = connection.CloseWithError(doqNoError, "")
				closeInBackground(packetConn)
				return nil, net.ErrClosed
			}
			d.mu.Unlock()
			go func() {
				<-connection.Context().Done()
				d.mu.Lock()
				delete(d.packetConns, packetConn)
				d.mu.Unlock()
				closeInBackground(packetConn)
			}()
			return connection, nil
		},
	}
	return roundTripper
}
