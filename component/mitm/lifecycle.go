// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
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

// Abort interrupts requests and workers immediately. Close then joins their
// cleanup without giving active connections a grace period.
func (h *Host) Abort() {
	h.forceCancel()
	h.mu.Lock()
	if h.cancel != nil {
		h.cancel()
	}
	h.mu.Unlock()
}

// Close drains active work, forcing cancellation when the grace period expires.
// Budget exhaustion is normal retirement; only resource cleanup errors are
// returned. In either case, all host work finishes before plugin resources close
// and the caller can retire routing, DNS and outbound state. Terminal callers
// must enforce a process deadline for work that does not honor cancellation.
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
	ctx, cancel := context.WithTimeout(h.forceContext, h.options.DrainTimeout)
	defer cancel()
	var shutdowns sync.WaitGroup
	for _, shutdown := range h.connections {
		shutdowns.Go(func() { _ = shutdown(ctx) })
	}
	h.mu.Unlock()
	finished := make(chan struct{})
	go func() {
		h.workers.Wait()
		shutdowns.Wait()
		h.serving.Wait()
		h.requests.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			h.options.Logger.WithField("drain_timeout", h.options.DrainTimeout).Debug("MITM drain deadline reached; forcing active connections to close")
		}
	}
	h.forceCancel()
	var forceCloses sync.WaitGroup
	h.mu.Lock()
	for conn := range h.connections {
		// One blocked transport must not prevent cancellation of the others.
		forceCloses.Go(func() { _ = conn.Close() })
	}
	h.mu.Unlock()
	// Join both request cleanup and forced socket closure before releasing any
	// plugin resources. The daemon's shutdown watchdog bounds a stuck join.
	forceCloses.Wait()
	<-finished
	h.options.Metrics.retire(h.metrics)
	for i := len(h.instances) - 1; i >= 0; i-- {
		if c, ok := h.instances[i].Plugin.(io.Closer); ok {
			h.closeErr = errors.Join(h.closeErr, c.Close())
		}
	}
	h.memoryLimit.Close()
	close(h.closeDone)
	return h.closeErr
}
