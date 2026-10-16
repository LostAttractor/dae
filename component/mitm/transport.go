// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

func (h *Host) httpTransport(dial DialContext) *http.Transport {
	transport := &http.Transport{
		DialContext:            dial,
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		TLSHandshakeTimeout:    10 * time.Second,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConnsPerHost:    8,
		MaxResponseHeaderBytes: 1 << 20,
	}
	if h.options.UpstreamTLSConfig != nil {
		transport.TLSClientConfig = h.options.UpstreamTLSConfig.Clone()
	}
	return transport
}

func (h *Host) http3Transport(dial DialPacketContext) *http3Upstream {
	transport := &http3.Transport{
		DisableCompression:     true,
		MaxResponseHeaderBytes: 1 << 20,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 10 * time.Second,
			MaxIdleTimeout:       90 * time.Second,
			MaxIncomingStreams:   -1,
		},
	}
	if h.options.UpstreamTLSConfig != nil {
		transport.TLSClientConfig = h.options.UpstreamTLSConfig.Clone()
	}
	closeCtx, cancel := context.WithCancel(context.Background())
	upstream := &http3Upstream{
		Transport: transport,
		cancel:    cancel, connections: make(map[*quic.Conn]struct{}),
	}
	transport.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
		upstream.mu.Lock()
		if upstream.closed {
			upstream.mu.Unlock()
			return nil, http3.ErrTransportClosed
		}
		// Register before dialing so Close also waits for failed / canceled
		// attempts, and no Add can race a zero-count Wait after closure.
		upstream.packets.Add(1)
		upstream.mu.Unlock()
		owned := false
		defer func() {
			if !owned {
				upstream.packets.Done()
			}
		}()
		ctx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(closeCtx, cancel)
		defer stop()
		defer cancel()
		packets, peer, err := dial(ctx, address)
		if err != nil {
			return nil, err
		}
		// Some outbound wrappers embed UDPConn while overriding WriteTo for
		// proxy framing or domain resolution. Do not let QUIC's optional OOB
		// or syscall fast paths bypass those selected-outbound semantics.
		quicTransport := &quic.Transport{Conn: struct{ net.PacketConn }{packets}}
		conn, err := quicTransport.Dial(ctx, peer, tlsConfig, config)
		if err != nil {
			_ = quicTransport.Close()
			_ = packets.Close()
			return nil, &upstreamQUICDialError{err}
		}
		upstream.mu.Lock()
		closed := upstream.closed
		if !closed {
			upstream.connections[conn] = struct{}{}
		}
		upstream.mu.Unlock()
		if closed {
			_ = conn.CloseWithError(0, "")
			_ = quicTransport.Close()
			_ = packets.Close()
			return nil, http3.ErrTransportClosed
		}
		owned = true
		go func() {
			defer upstream.packets.Done()
			<-conn.Context().Done()
			_ = quicTransport.Close()
			_ = packets.Close()
			upstream.mu.Lock()
			delete(upstream.connections, conn)
			upstream.mu.Unlock()
		}()
		return conn, nil
	}
	return upstream
}

// Own every packet connection, including connections evicted after a stream
// error. Request cancellation bounds active exchanges, including header waits.
type http3Upstream struct {
	*http3.Transport
	packets     sync.WaitGroup
	mu          sync.Mutex
	connections map[*quic.Conn]struct{}
	closed      bool
	cancel      context.CancelFunc
	closeOnce   sync.Once
	closeErr    error
}

func (t *http3Upstream) Close() error {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		t.cancel()
		connections := make([]*quic.Conn, 0, len(t.connections))
		for conn := range t.connections {
			connections = append(connections, conn)
		}
		t.mu.Unlock()
		// A stream error can evict a live connection from http3.Transport.
		// Close every connection we own, including those no longer in its pool.
		for _, conn := range connections {
			_ = conn.CloseWithError(0, "")
		}
		t.closeErr = t.Transport.Close()
		t.packets.Wait()
	})
	return t.closeErr
}
