// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

// DialPacketContext opens an upstream packet connection using the selected
// outbound and returns its destination address. The host owns the returned
// connection. Implementations must honor ctx and preserve datagram boundaries.
type DialPacketContext func(context.Context, string) (net.PacketConn, net.Addr, error)

// ServePacketConn serves HTTP/3 connections on an intercepted UDP association.
// Both original flow addresses are required. conn must exclusively carry packets
// from flow.Source to flow.Destination; cross-association migration is not supported.
// The caller expires idle
// associations by closing conn. Intercepted requests use HTTP/3 upstream;
// auxiliary plugin HTTP requests use dial, with no implicit UDP-to-TCP fallback.
func (h *Host) ServePacketConn(conn net.PacketConn, flow plugin.Flow, dial DialContext, dialPacket DialPacketContext) error {
	if err := h.track(conn); err != nil {
		_ = conn.Close()
		return err
	}
	defer h.untrack(conn)
	if h.options.Authority == nil {
		return errors.New("mitm: HTTP/3 requires a CA")
	}
	if dialPacket == nil {
		return errors.New("mitm: HTTP/3 requires a packet dialer")
	}
	if !flow.Source.IsValid() || !flow.Destination.IsValid() {
		return errors.New("mitm: HTTP/3 requires the original source and destination")
	}
	cfg := h.options.Authority.TLSConfig(flow.Host)
	cfg.MinVersion = tls.VersionTLS13
	cfg.NextProtos = []string{http3.NextProtoH3}
	transport := &quic.Transport{
		Conn: conn,
		ConnContext: func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
			peer, err := netip.ParseAddrPort(info.RemoteAddr.String())
			if err != nil || peer.Addr().Unmap() != flow.Source.Addr().Unmap() || peer.Port() != flow.Source.Port() {
				return nil, errors.New("mitm: QUIC peer differs from intercepted source")
			}
			return ctx, nil
		},
	}
	defer transport.Close()
	listener, err := transport.Listen(cfg, &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       90 * time.Second,
		MaxIncomingStreams:   64,
		Allow0RTT:            false,
	})
	if err != nil {
		return fmt.Errorf("mitm QUIC listener: %w", err)
	}
	defer listener.Close()
	var connections sync.WaitGroup
	defer connections.Wait()
	server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Context().Value(http3HandlerKey{}).(http.Handler).ServeHTTP(w, r)
		}),
		MaxHeaderBytes: 1 << 20,
		IdleTimeout:    90 * time.Second,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			upstream := h.http3Transport(dialPacket)
			auxiliary := h.httpTransport(dial)
			handler := h.handlerForFlow("https", flow, upstream, &http.Client{Transport: auxiliary})
			connections.Add(1)
			go func() {
				defer connections.Done()
				<-conn.Context().Done()
				_ = upstream.Close()
				auxiliary.CloseIdleConnections()
			}()
			ctx = plugin.WithIDs(ctx, strconv.FormatUint(serial.Add(1), 10), "")
			return context.WithValue(ctx, http3HandlerKey{}, handler)
		},
	}
	if err := h.attach(conn, server.Shutdown); err != nil {
		return err
	}
	err = server.ServeListener(listener)
	_ = listener.Close()
	// ServeListener returns when GOAWAY stops Accept, before active streams
	// finish. Wait for them before closing the association or its transports.
	_ = server.Shutdown(h.forceContext)
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

type http3HandlerKey struct{}
