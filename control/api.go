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

func (c *ControlPlane) APIHandler(version string, operations apiserver.OperationStore, certificates *apiserver.Certificates) http.Handler {
	return c.apiHandler(version, c.resolveAPIClient, operations, certificates)
}

func (c *ControlPlane) apiHandler(version string, resolve apiserver.ClientResolver, operations apiserver.OperationStore, certificates *apiserver.Certificates) http.Handler {
	options := apiserver.Options{Selectors: c, Probes: c, Devices: c, ResolveClient: resolve, APIKey: c.apiKey, Operations: operations, Diagnostics: c}
	options.Status = func() *contract.StatusSnapshot { return c.StatusSnapshot(version) }
	options.DeviceStatus = c.DeviceStatus
	if host := c.MITMHost(); host != nil {
		options.Scripts = host
	}
	options.Certificates = certificates
	if tests := c.MITMTests(); tests != nil {
		options.MITMTests = tests
		if certificates != nil {
			copy := *certificates
			copy.Identity.MITMTestGeneration = tests.Generation()
			copy.Identity.MITMTestOrigins = tests.Origins()
			options.Certificates = &copy
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

func (c *ControlPlane) resolveAPIClient(source, destination netip.AddrPort) (apiserver.ClientIdentity, error) {
	client, err := c.resolveAPIObservation(source, destination)
	if err != nil {
		return apiserver.ClientIdentity{}, err
	}
	linkType := "ethernet"
	if client.LinkType == 2 {
		linkType = "ip"
	}
	return apiserver.ClientIdentity{LinkType: linkType, MAC: client.Mac, IfIndex: client.Ifindex, PhysicalIfIndex: client.Physinif}, nil
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
	// Only LAN hooks write this generation's map. An attachment removed since
	// observation must no longer authorize requests, even within the TTL.
	if uint64(now.Nano())-client.ObservedAt > uint64(apiClientTTL) {
		return bpfApiClient{}, fmt.Errorf("device API LAN ingress observation expired; retry the request")
	}
	if c.core.kernelLinks == nil {
		return bpfApiClient{}, fmt.Errorf("LAN ingress attachment unavailable")
	}
	if _, attached := c.core.hostTCXLink(int(client.Ifindex), hostTCXLanIngress); !attached {
		return bpfApiClient{}, fmt.Errorf("observed LAN ingress is no longer attached")
	}
	if err := netutils.ValidateClientScope(source.Addr(), destination.Addr(), int(client.Ifindex)); err != nil {
		return bpfApiClient{}, err
	}
	switch client.LinkType {
	case 1:
		if err := netutils.ValidateClientMAC(source.Addr(), client.Mac); err != nil {
			return bpfApiClient{}, err
		}
	case 2:
		if client.Mac != [6]byte{} {
			return bpfApiClient{}, fmt.Errorf("IP ingress cannot supply an Ethernet MAC")
		}
	default:
		return bpfApiClient{}, fmt.Errorf("unknown LAN ingress link type")
	}
	return client, nil
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
