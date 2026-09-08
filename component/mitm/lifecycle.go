// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// Track the underlying TCP connection or UDP association before any handshake.
// Until its HTTP server is attached, draining closes the raw connection.
func (h *Host) track(conn io.Closer) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return net.ErrClosed
	}
	h.connections[conn] = func(context.Context) error { return conn.Close() }
	h.serving.Add(1)
	return nil
}

func (h *Host) attach(conn io.Closer, shutdown func(context.Context) error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return net.ErrClosed
	}
	h.connections[conn] = shutdown
	return nil
}

func (h *Host) untrack(conn io.Closer) {
	_ = conn.Close()
	h.mu.Lock()
	delete(h.connections, conn)
	h.mu.Unlock()
	h.serving.Done()
}

// Close drains active work, forcing cancellation when the grace period expires.
// Budget exhaustion is normal retirement; only resource cleanup errors are
// returned. In either case, all host work finishes before plugin resources close
// and the caller can retire routing, DNS and outbound state.
func (h *Host) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		<-h.closeDone
		return h.closeErr
	}
	h.closed = true
	if h.cancel != nil {
		h.cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), h.options.DrainTimeout)
	defer cancel()
	var shutdowns sync.WaitGroup
	for _, shutdown := range h.connections {
		shutdowns.Go(func() { _ = shutdown(ctx) })
	}
	h.mu.Unlock()
	finished := make(chan error, 1)
	go func() {
		h.workers.Wait()
		shutdowns.Wait()
		h.serving.Wait()
		h.requests.Wait()
		var errs []error
		for i := len(h.instances) - 1; i >= 0; i-- {
			if c, ok := h.instances[i].Plugin.(io.Closer); ok {
				errs = append(errs, c.Close())
			}
		}
		finished <- errors.Join(errs...)
	}()
	forced := false
	select {
	case h.closeErr = <-finished:
	case <-ctx.Done():
		forced = true
		if h.options.Log != nil {
			h.options.Log(fmt.Sprintf("mitm: drain timeout after %s; forcing active connections to close", h.options.DrainTimeout))
		}
	}
	h.forceCancel()
	h.mu.Lock()
	var remaining []io.Closer
	for conn := range h.connections {
		remaining = append(remaining, conn)
	}
	h.mu.Unlock()
	for _, conn := range remaining {
		_ = conn.Close()
	}
	if forced {
		// Cancellation and socket closure unblock streams, uploads, WebSockets
		// and upstream dials. Join their cleanup before retiring shared state.
		h.closeErr = <-finished
	}
	close(h.closeDone)
	return h.closeErr
}
