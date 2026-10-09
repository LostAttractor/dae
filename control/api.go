// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	contract "github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/internal/apiserver"
	"golang.org/x/sys/unix"
)

func (c *ControlPlane) APIHandler(version string, resources apiserver.ResourceStore) http.Handler {
	return c.apiHandler(version, c.resolveAPIClient, resources)
}

func (c *ControlPlane) apiHandler(version string, resolve apiserver.ClientResolver, resources apiserver.ResourceStore) http.Handler {
	options := apiserver.Options{Selectors: c, Probes: c, Devices: c, ResolveClient: resolve, APIKey: c.apiKey, Resources: resources}
	options.Status = func() *contract.StatusSnapshot { return c.StatusSnapshot(version) }
	if host := c.MITMHost(); host != nil {
		options.Scripts = host
	}
	if authority := c.mitmAuthority(); authority != nil {
		options.Certificates = &apiserver.Certificates{Identity: authority.Identity(), Handler: authority.Handler()}
	}
	return apiserver.NewHandler(options)
}

// Each request refreshes the entry at the LAN hook, including keep-alive data.
const apiClientTTL = 30 * time.Second

func apiClientKey(source, destination netip.AddrPort) bpfTuplesKey {
	key := bpfTuplesKey{Sport: common.Htons(source.Port()), Dport: common.Htons(destination.Port()), L4proto: unix.IPPROTO_TCP}
	key.Sip.U6Addr8 = source.Addr().As16()
	key.Dip.U6Addr8 = destination.Addr().As16()
	return key
}

func (c *ControlPlane) resolveAPIClient(source, destination netip.AddrPort) ([6]byte, error) {
	if len(c.lanInterface) == 0 {
		return [6]byte{}, fmt.Errorf("device API requires a configured LAN interface (global.lan_interface)")
	}
	key := apiClientKey(source, destination)
	var client bpfApiClient
	if err := c.core.bpf.ApiClientMap.Lookup(&key, &client); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return [6]byte{}, fmt.Errorf("device API requires a connection observed on global.lan_interface")
		}
		return [6]byte{}, fmt.Errorf("read device API ingress: %w", err)
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return [6]byte{}, fmt.Errorf("read device API observation clock: %w", err)
	}
	// Only LAN hooks write this map, and reload clears it before the new
	// hooks attach. Re-resolving interface names would duplicate that boundary.
	if uint64(now.Nano())-client.ObservedAt > uint64(apiClientTTL) {
		return [6]byte{}, fmt.Errorf("device API LAN ingress observation expired; retry the request")
	}
	if err := netutils.ValidateClientMAC(source.Addr(), client.Mac); err != nil {
		return [6]byte{}, err
	}
	return client.Mac, nil
}

// Initialize this generation's private observation map and port. Old API
// requests keep their own observations until Runtime publishes the successor.
func (c *ControlPlane) publishAPIObservation() error {
	var key bpfTuplesKey
	for {
		if err := c.core.bpf.ApiClientMap.NextKey(nil, &key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return fmt.Errorf("iterate device API ingress observations: %w", err)
		}
		if err := c.core.bpf.ApiClientMap.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("clear device API ingress observations: %w", err)
		}
	}
	if err := c.core.bpf.ApiPort.Set(common.Htons(c.apiPort)); err != nil {
		return fmt.Errorf("publish device API observation port: %w", err)
	}
	return nil
}
