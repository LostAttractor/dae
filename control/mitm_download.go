// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/internal/pluginctx"
)

func newMITMClient(c *ControlPlane, timeout time.Duration) (*http.Client, func()) {
	lifetime, cancel := context.WithCancel(context.Background())
	var dials sync.RWMutex
	dial := mitmClientDialContext(c)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.RLock()
				defer dials.RUnlock()
				if lifetime.Err() != nil {
					return nil, net.ErrClosed
				}
				ctx, cancelDial := context.WithCancel(ctx)
				stop := context.AfterFunc(lifetime, cancelDial)
				defer func() {
					stop()
					cancelDial()
				}()
				return dial(ctx, network, address)
			},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: timeout,
		},
		Timeout: timeout,
	}
	return client, func() {
		cancel()
		client.CloseIdleConnections()
		// Transport may outlive a canceled request. Join its dials before the
		// constructor installs the final routing matcher.
		dials.Lock()
		dials.Unlock()
	}
}

// NewPreparationClient routes bounded resource downloads through this plane.
func (c *ControlPlane) NewPreparationClient() (*http.Client, func()) {
	return newMITMClient(c, 30*time.Second)
}

// NewWorkerClient belongs to the daemon. Every request selects the
// current plane, so unchanged plugin workers do not capture a retired plane.
func (r *Runtime) NewWorkerClient() (*http.Client, func()) {
	client, closeClient := mitm.NewRoutedHTTPClient(func(request *http.Request) (mitm.UpstreamPlan, error) {
		plane := request.Context().Value(workerPlaneKey{}).(*ControlPlane)
		planner := &httpRoutePlanner{plane: plane, network: "tcp", identity: daemonProcessIdentity()}
		return planner.plan(request)
	})
	client.Transport = &workerTransport{runtime: r, next: client.Transport}
	return client, closeClient
}

type workerPlaneKey struct{}

type workerTransport struct {
	runtime *Runtime
	next    http.RoundTripper
}

func (t *workerTransport) RoundTripPolicy(request *http.Request, policy string) (*http.Response, error) {
	return t.RoundTrip(request.WithContext(pluginctx.WithHTTPPolicy(request.Context(), policy)))
}

func (t *workerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.runtime.mu.Lock()
	plane := t.runtime.current
	if plane != nil {
		plane.workerRoundTrips.Add(1)
	}
	t.runtime.mu.Unlock()
	if plane == nil {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		if err := request.Context().Err(); err != nil {
			return nil, err
		}
		return nil, net.ErrClosed
	}
	// Routing and connection establishment need the plane. After headers, the
	// response owns its transport connection and its existing resource leases.
	defer plane.workerRoundTrips.Done()
	request = request.WithContext(context.WithValue(request.Context(), workerPlaneKey{}, plane))
	return t.next.RoundTrip(request)
}

// Downloads originate in the daemon, before any client socket exists. Match
// its process name and an unspecified source, never a fabricated LAN device.
func mitmClientDialContext(c *ControlPlane) mitm.DialContext {
	process := daemonProcessIdentity()
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		target, err := parseHTTPTarget(address)
		if err != nil {
			return nil, err
		}
		var failures []error
		for option, err := range c.httpRouteCandidates(ctx, network, target, netip.AddrPort{}, process) {
			if err != nil {
				failures = append(failures, err)
				continue
			}
			conn, err := dialHTTPUpstream(ctx, option)
			logHTTPDial(netip.AddrPort{}, target.host, option, err)
			if err == nil {
				return conn, nil
			}
			failures = append(failures, err)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("mitm client %s: %w", address, errors.Join(failures...))
	}
}
