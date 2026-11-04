// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/api"
)

func (c *ControlPlane) kernelTableStatuses() []api.TableUsage {
	if c.core == nil || c.core.bpf == nil || c.core.bpf.bpfObjects == nil {
		return nil
	}
	b := c.core.bpf
	targets := []struct {
		name string
		m    *ebpf.Map
	}{
		{"tcp_flow_map", b.TcpFlowMap},
		{"routing_tuples_map", b.RoutingTuplesMap},
		{"udp_conn_state_map", b.UdpConnStateMap},
		{"udp_routing_cache_map", b.UdpRoutingCacheMap},
		{"udp_bindings_map", b.UdpBindingsMap},
		{"udp_inbound_pending_map", b.UdpInboundPendingMap},
		{"redirect_track", b.RedirectTrack},
		{"api_client_map", b.ApiClientMap},
		{"fallback_lease_map", b.FallbackLeaseMap},
		{"outbound_connectivity_map", b.OutboundConnectivityMap},
		{"routing_profile_map", b.RoutingProfileMap},
		{"routing_interface_map", b.RoutingInterfaceMap},
		{"route_exempt_map", b.RouteExemptMap},
	}
	var tables []api.TableUsage
	var ids []ebpf.MapID
	var positions []int
	add := func(name string, m *ebpf.Map, cacheID bool) {
		if m == nil {
			return
		}
		usage := api.TableUsage{Name: name, Scope: "kernel", Limit: int(m.MaxEntries()), OnFull: "reject"}
		if m.Type() == ebpf.LRUHash {
			usage.OnFull = "evict"
		}
		id, err := c.core.tableReader.mapID(m, cacheID)
		if err != nil {
			usage.Error = err.Error()
		} else {
			ids = append(ids, id)
			positions = append(positions, len(tables))
		}
		tables = append(tables, usage)
	}
	for _, target := range targets {
		add(target.name, target.m, true)
	}
	if b.DeviceRoutesMap != nil {
		var devices *ebpf.Map
		if err := b.DeviceRoutesMap.Lookup(uint32(0), &devices); err == nil {
			defer devices.Close()
			add("device_routes_map", devices, false)
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			usage := api.TableUsage{Name: "device_routes_map", Scope: "kernel", OnFull: "reject", Error: err.Error()}
			if spec, specErr := parsedBPFSpec(); specErr == nil {
				usage.Limit = int(spec.Maps["device_routes_map"].InnerMap.MaxEntries)
			}
			tables = append(tables, usage)
		}
	}
	if len(ids) != 0 {
		counts, err := c.core.tableReader.read(ids)
		for i, id := range ids {
			usage := &tables[positions[i]]
			if err != nil {
				usage.Error = err.Error()
			} else if used, ok := counts[id]; ok {
				usage.Used = used
			} else {
				usage.Error = "kernel map counter unavailable"
			}
		}
	}
	// Arrays are allocated in full; report compiled slots, not allocated cells.
	if m := c.routingMatcher; m != nil && m.routingState != nil {
		if b.RoutingMap != nil {
			tables = append(tables, api.TableUsage{Name: "routing_map", Scope: "kernel", Used: m.routing.end, Limit: int(b.RoutingMap.MaxEntries()), OnFull: "reject"})
		}
		if b.LpmArrayMap != nil {
			tables = append(tables, api.TableUsage{Name: "lpm_array_map", Scope: "kernel", Used: m.kernelLpmLen, Limit: int(b.LpmArrayMap.MaxEntries()), OnFull: "reject"})
		}
	}
	return tables
}

func (c *ControlPlane) userspaceTableStatuses() []api.TableUsage {
	if c.udpEndpoints == nil {
		return nil
	}
	pool := c.udpEndpoints
	used, limit := pool.packetBudget().Usage()
	replies, replyLimit := DefaultAnyfromPool.usage()
	return []api.TableUsage{
		{Name: "udp-sources", Scope: "userspace", Used: int(pool.sources.Load()), Limit: pool.sourceCapacity(), OnFull: "reject"},
		{Name: "udp-packet-resources", Scope: "userspace", Used: used, Limit: limit, OnFull: "reject"},
		{Name: "udp-reply-sockets", Scope: "userspace", Used: replies, Limit: replyLimit, OnFull: "reject"},
	}
}
