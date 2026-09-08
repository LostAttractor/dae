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
	select {
	case h.closeErr = <-finished:
	case <-ctx.Done():
		h.closeErr = fmt.Errorf("mitm: drain deadline exceeded: %w", ctx.Err())
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
	close(h.closeDone)
	return h.closeErr
}
