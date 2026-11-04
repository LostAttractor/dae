// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func TestKernelTableCounters(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated kernel counter tests")
	}
	create := func(kind ebpf.MapType, limit uint32) *ebpf.Map {
		t.Helper()
		m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "table_fixture", Type: kind, KeySize: 4, ValueSize: 4, MaxEntries: limit})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Close() })
		return m
	}
	hash, lru, unrelated := create(ebpf.Hash, 8), create(ebpf.LRUHash, 4), create(ebpf.Hash, 16)
	for i := uint32(0); i < 12; i++ {
		if err := lru.Update(i, i, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	for i := uint32(0); i < 3; i++ {
		if err := hash.Update(i, i, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if err := unrelated.Update(i, i, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	core := &controlPlaneCore{bpf: &BPFState{bpfObjects: &bpfObjects{TcpFlowMap: lru, UdpBindingsMap: hash}}}
	t.Cleanup(func() { _ = core.tableReader.Close() })
	plane := &ControlPlane{core: core}
	for _, expected := range []int{3, 2} {
		iterator := core.tableReader.iterator
		tables := plane.tableStatuses()
		if iterator != nil && core.tableReader.iterator != iterator {
			t.Fatal("sampling replaced the reader's iterator link")
		}
		if len(core.tableReader.ids) != 2 {
			t.Fatalf("fixed map IDs were not retained: %v", core.tableReader.ids)
		}
		if len(tables) != 2 {
			t.Fatalf("sample included unrelated maps: %+v", tables)
		}
		for _, usage := range tables {
			if usage.Error != "" || usage.Scope != "kernel" {
				t.Fatalf("counter unavailable: %+v", usage)
			}
			switch usage.Name {
			case "tcp_flow_map":
				if usage.Used != 4 || usage.Limit != 4 || usage.OnFull != "evict" {
					t.Fatalf("LRU count after eviction: %+v", usage)
				}
			case "udp_bindings_map":
				if usage.Used != expected || usage.Limit != 8 || usage.OnFull != "reject" {
					t.Fatalf("hash count: %+v", usage)
				}
			default:
				t.Fatalf("unrequested map: %+v", usage)
			}
		}
		if expected == 3 {
			if err := hash.Delete(uint32(0)); err != nil {
				t.Fatal(err)
			}
		}
	}
	devices, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1,
		InnerMap: &ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = devices.Close() })
	core.bpf.DeviceRoutesMap = devices
	for _, current := range []*ebpf.Map{hash, create(ebpf.Hash, 8)} {
		if err := devices.Update(uint32(0), current, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		want := 0
		if current == hash {
			want = 2
		}
		tables := plane.tableStatuses()
		if len(tables) != 3 || tables[2].Name != "device_routes_map" || tables[2].Error != "" || tables[2].Used != want {
			t.Fatalf("sampling did not follow the current inner map: %+v", tables)
		}
		if len(core.tableReader.ids) != 2 {
			t.Fatal("sampling retained a borrowed inner-map descriptor")
		}
	}
	if err := hash.Close(); err != nil {
		t.Fatal(err)
	}
	for _, usage := range plane.tableStatuses() {
		if usage.Name == "udp_bindings_map" && usage.Error == "" {
			t.Fatal("a failed counter was reported as empty")
		}
	}
	if err := core.tableReader.Close(); err != nil {
		t.Fatal(err)
	}
	if stream, err := core.tableReader.iterator.Open(); err == nil {
		_ = stream.Close()
		t.Fatal("reader close retained the iterator link")
	}
	if core.tableReader.objects.ReadMapUsage.FD() >= 0 || core.tableReader.ids != nil {
		t.Fatal("reader close retained its program or map IDs")
	}
}

func TestKernelTableReaderClosed(t *testing.T) {
	var reader kernelTableReader
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.read(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed reader reloaded BPF resources: %v", err)
	}
	if _, err := reader.mapID(nil, true); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed reader inspected a map: %v", err)
	}
}

func TestStatusTablesUseRuntimeUDPBudgets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := &UdpEndpointPool{sourceLimit: 3, resources: netproxy.NewPacketBudget(2)}
		defer pool.closeAll()
		src, dst := netip.MustParseAddrPort("203.0.113.1:40000"), netip.MustParseAddrPort("192.0.2.1:443")
		endpoint, _ := resourceUDPEndpoint(t, src)
		pool.add(src, endpoint)
		if _, err := endpoint.socket(t.Context(), time.Time{}, pool, src, dst, nil); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			// Both generations borrow the same pool; neither creates another count.
			plane := &ControlPlane{udpEndpoints: pool}
			tables := plane.tableStatuses()
			if len(tables) != 3 {
				t.Fatalf("userspace tables depended on a domain registry: %+v", tables)
			}
			for _, usage := range tables {
				if usage.Scope != "userspace" || usage.OnFull != "reject" || usage.Error != "" {
					t.Fatalf("invalid userspace usage: %+v", usage)
				}
				switch usage.Name {
				case "udp-sources":
					if usage.Used != 1 || usage.Limit != 3 {
						t.Fatalf("source usage: %+v", usage)
					}
				case "udp-packet-resources":
					if usage.Used != 1 || usage.Limit != 2 {
						t.Fatalf("resource usage: %+v", usage)
					}
				case "udp-reply-sockets":
					if usage.Limit != maxUDPSources {
						t.Fatalf("reply socket limit: %+v", usage)
					}
				default:
					t.Fatalf("unexpected table: %+v", usage)
				}
			}
		}
	})
}
