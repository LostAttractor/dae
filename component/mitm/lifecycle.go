// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/dae/component/pluginhost"
)

// Track an admitted TCP connection or UDP association before any handshake.
// Until its HTTP server is attached, draining closes the raw connection.
func (h *Host) track(conn io.Closer) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.forceContext.Err() != nil {
		return net.ErrClosed
	}
	h.connections[conn] = func(context.Context) error { return conn.Close() }
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
}

// Abort interrupts requests and workers immediately. Close then joins their
// cleanup without giving active connections a grace period.
func (h *Host) Abort() {
	h.forceCancel()
	h.mu.Lock()
	h.stopWorkersLocked()
	h.mu.Unlock()
}

// DrainFor flushes replaced instances while keeping reused workers active.
// abort skips the drain grace period but still waits for final cleanup.
// Callers must first retire earlier hosts, then release after starting or abandoning next.
func (h *Host) DrainFor(next *Host, abort bool) (func(), error) {
	if h == nil || h.SameInstances(next) {
		return func() {}, nil
	}
	var retained []*pluginhost.Instance
	release := func() {
		for _, instance := range retained {
			instance.Deactivate()
		}
	}
	for _, instance := range next.Instances() {
		for _, previous := range h.instances {
			if instance != previous.owner {
				continue
			}
			if _, err := instance.Activate(next.options.HTTPClient); err != nil {
				release()
				return nil, err
			}
			retained = append(retained, instance)
			break
		}
	}
	if abort {
		h.Abort()
	}
	if err := h.Close(); err != nil {
		release()
		return nil, err
	}
	return release, nil
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
	h.stopWorkersLocked()
	ctx, cancel := context.WithTimeout(h.forceContext, h.options.DrainTimeout)
	defer cancel()
	var shutdowns sync.WaitGroup
	for _, shutdown := range h.connections {
		shutdowns.Go(func() { _ = shutdown(ctx) })
	}
	h.mu.Unlock()
	finished := make(chan struct{})
	go func() {
		shutdowns.Wait()
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
		h.closeErr = errors.Join(h.closeErr, h.instances[i].owner.Release())
	}
	h.memoryLimit.Close()
	close(h.closeDone)
	return h.closeErr
}
