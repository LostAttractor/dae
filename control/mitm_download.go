// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
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

// Downloads originate in the daemon, before any client socket exists. Match
// its process name and an unspecified source, never a fabricated LAN device.
func mitmClientDialContext(c *ControlPlane) mitm.DialContext {
	processName, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		processName = []byte(filepath.Base(os.Args[0]))
	}
	process := bpfRoutingResult{Pid: uint32(os.Getpid())}
	copy(process.Pname[:], strings.TrimSpace(string(processName)))
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
			conn, err := c.dialHTTPUpstream(ctx, option)
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
