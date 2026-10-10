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
	options := apiserver.Options{Selectors: c, Probes: c, Devices: c, ResolveClient: resolve, APIKey: c.apiKey, Resources: resources, Diagnostics: c}
	if c.core != nil && c.core.bpf != nil && c.core.bpf.ApiClientMap != nil {
		options.ResolveContext = c.resolveDiagnosticContext
	}
	options.Status = func() *contract.StatusSnapshot { return c.StatusSnapshot(version) }
	options.DeviceStatus = c.DeviceStatus
	if host := c.MITMHost(); host != nil {
		options.Scripts = host
	}
	if authority := c.mitmAuthority(); authority != nil {
		options.Certificates = &apiserver.Certificates{Identity: authority.Identity(), Handler: authority.Handler()}
		if tests := c.CertificateTests(); tests != nil {
			options.CertificateTests = tests
			options.Certificates.Identity.TestAvailable = true
			options.Certificates.Identity.TestGeneration = tests.Generation()
			options.Certificates.Identity.TestMITMOrigins = tests.Origins()
		}
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
	client, err := c.resolveAPIObservation(source, destination)
	return client.Mac, err
}

func (c *ControlPlane) resolveAPIObservation(source, destination netip.AddrPort) (bpfApiClient, error) {
	if len(c.lanInterface) == 0 {
		return bpfApiClient{}, fmt.Errorf("device API requires a configured LAN interface (global.lan_interface)")
	}
	key := apiClientKey(source, destination)
	var client bpfApiClient
	if err := c.core.bpf.ApiClientMap.Lookup(&key, &client); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return bpfApiClient{}, fmt.Errorf("device API requires a connection observed on global.lan_interface")
		}
		return bpfApiClient{}, fmt.Errorf("read device API ingress: %w", err)
	}
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return bpfApiClient{}, fmt.Errorf("read device API observation clock: %w", err)
	}
	// Only LAN hooks write this map, and reload clears it before the new
	// hooks attach. Re-resolving interface names would duplicate that boundary.
	if uint64(now.Nano())-client.ObservedAt > uint64(apiClientTTL) {
		return bpfApiClient{}, fmt.Errorf("device API LAN ingress observation expired; retry the request")
	}
	if err := netutils.ValidateClientMAC(source.Addr(), client.Mac); err != nil {
		return bpfApiClient{}, err
	}
	return client, nil
}

func (c *ControlPlane) resolveDiagnosticContext(source, destination netip.AddrPort) (contract.DiagnosticContext, error) {
	client, err := c.resolveAPIObservation(source, destination)
	if err != nil {
		return contract.DiagnosticContext{}, err
	}
	mac := client.Mac
	return contract.DiagnosticContext{Origin: "lan", SourceIP: source.Addr().Unmap().WithZone("").String(), MAC: fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]), IfIndex: new(client.Ifindex), PhysicalIfIndex: new(client.Physinif)}, nil
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
