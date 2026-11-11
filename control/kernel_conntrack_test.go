// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestConntrackProbeStandalone(t *testing.T) {
	spec, err := loadBPFSpec()
	if err != nil {
		t.Fatal(err)
	}
	program := spec.Programs["conntrack_probe"]
	if program == nil || program.Type != ebpf.SchedCLS {
		t.Fatal("missing TC conntrack probe")
	}
	for _, instruction := range program.Instructions {
		if instruction.IsLoadFromMap() {
			t.Fatalf("conntrack probe requires collection maps: %s", instruction.Reference())
		}
	}
}

func TestConntrackProbeLoadFailure(t *testing.T) {
	for _, spec := range []*ebpf.CollectionSpec{
		{},
		{Programs: map[string]*ebpf.ProgramSpec{"conntrack_probe": {}}},
	} {
		program, err := loadConntrackProbe(spec)
		if program != nil {
			program.Close()
			t.Fatal("invalid probe loaded")
		}
		if err == nil || !strings.Contains(err.Error(), "load conntrack probe") {
			t.Fatalf("incorrect load failure classification: %v", err)
		}
	}
}

func TestConntrackFamilyDirections(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			var tuples [][2]netip.AddrPort
			err := probeConntrackFamily(t.Context(), network, func(source, destination netip.AddrPort) (uint32, error) {
				if source.Port() == 0 || destination.Port() == 0 || source == destination ||
					!source.Addr().IsLoopback() || !destination.Addr().IsLoopback() || source.Addr().Is4() != (network == "udp4") {
					t.Fatalf("invalid loopback tuple: %s -> %s", source, destination)
				}
				tuples = append(tuples, [2]netip.AddrPort{source, destination})
				return []uint32{0, 0, 1, 2}[len(tuples)-1], nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(tuples) != 4 || tuples[0] != tuples[2] || tuples[1] != tuples[3] || tuples[0] != [2]netip.AddrPort{tuples[1][1], tuples[1][0]} {
				t.Fatalf("did not check both fresh and established directions: %v", tuples)
			}
		})
	}
}

func TestConntrackFamilyFailures(t *testing.T) {
	negativeEINVAL := uint32(0xffffffff - uint32(unix.EINVAL) + 1)
	for _, test := range []struct {
		name     string
		results  []uint32
		queryErr error
		want     string
		wantErr  error
	}{
		{name: "tracking disabled", results: []uint32{0, 0, 0}, want: "direction ORIGINAL after UDP round trip: got 0"},
		{name: "wrong original", results: []uint32{0, 0, 2}, want: "direction ORIGINAL after UDP round trip: got 2"},
		{name: "wrong reply", results: []uint32{0, 0, 1, 1}, want: "direction REPLY after UDP round trip: got 1"},
		{name: "fresh lookup errno", results: []uint32{negativeEINVAL}, want: "fresh tuple lookup", wantErr: unix.EINVAL},
		{name: "direction lookup errno", results: []uint32{0, 0, negativeEINVAL}, want: "direction ORIGINAL after UDP round trip: lookup error", wantErr: unix.EINVAL},
		{name: "unexpected result", results: []uint32{3}, want: "unexpected lookup result 3"},
		{name: "test run denied", queryErr: os.ErrPermission, want: "BPF TestRun", wantErr: os.ErrPermission},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			err := probeConntrackFamily(t.Context(), "udp4", func(netip.AddrPort, netip.AddrPort) (uint32, error) {
				if test.queryErr != nil {
					return 0, test.queryErr
				}
				result := test.results[calls]
				calls++
				return result, nil
			})
			if err == nil || !strings.Contains(err.Error(), test.want) || (test.wantErr != nil && !errors.Is(err, test.wantErr)) {
				t.Fatalf("incorrect failure classification: %v", err)
			}
		})
	}
}

func TestConntrackFamilyRetriesOccupiedTuples(t *testing.T) {
	for _, busyDirection := range []int{0, 1} {
		t.Run([]string{"original", "reply"}[busyDirection], func(t *testing.T) {
			results := []uint32{1, 0, 0, 1, 2}
			if busyDirection == 1 {
				results = []uint32{0, 2, 0, 0, 1, 2}
			}
			calls := 0
			err := probeConntrackFamily(t.Context(), "udp4", func(netip.AddrPort, netip.AddrPort) (uint32, error) {
				result := results[calls]
				calls++
				return result, nil
			})
			if err != nil || calls != len(results) {
				t.Fatalf("did not retry occupied tuple: calls=%d err=%v", calls, err)
			}
		})
	}
	calls := 0
	err := probeConntrackFamily(t.Context(), "udp4", func(netip.AddrPort, netip.AddrPort) (uint32, error) {
		calls++
		return 1, nil
	})
	if err == nil || !strings.Contains(err.Error(), "fresh tuple selection") || calls != 8 {
		t.Fatalf("tuple retries are not bounded: calls=%d err=%v", calls, err)
	}
}

func TestConntrackFamilyCancellationAndSocketFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := probeConntrackFamily(ctx, "udp4", func(netip.AddrPort, netip.AddrPort) (uint32, error) {
		t.Fatal("queried conntrack after cancellation")
		return 0, nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	if err := probeConntrackFamily(ctx, "udp4", func(netip.AddrPort, netip.AddrPort) (uint32, error) {
		calls++
		if calls == 2 {
			cancel()
		}
		return 0, nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation during the round trip: %v", err)
	}
	if err := probeConntrackFamily(t.Context(), "invalid", nil); err == nil || !strings.Contains(err.Error(), "UDP socket: bind client") {
		t.Fatalf("lost socket failure: %v", err)
	}
}

func TestConntrackNonceValidation(t *testing.T) {
	for _, test := range []struct {
		name      string
		payload   []byte
		wrongPeer bool
	}{
		{name: "valid", payload: []byte("nonce")},
		{name: "wrong nonce", payload: []byte("other")},
		{name: "truncated nonce", payload: []byte("nonc")},
		{name: "oversized nonce", payload: []byte("nonce extra")},
		{name: "wrong peer", payload: []byte("nonce"), wrongPeer: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := conntrackTestSocket(t)
			server := conntrackTestSocket(t)
			peer := client.LocalAddr().(*net.UDPAddr).AddrPort()
			if test.wrongPeer {
				peer = server.LocalAddr().(*net.UDPAddr).AddrPort()
			}
			if _, err := client.WriteToUDP(test.payload, server.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Fatal(err)
			}
			err := readConntrackNonce(server, []byte("nonce"), peer)
			if (err != nil) != (test.name != "valid") {
				t.Fatalf("incorrect nonce validation: %v", err)
			}
		})
	}
	client, server := conntrackTestSocket(t), conntrackTestSocket(t)
	if err := client.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conntrackNonceRoundTrip(client, server); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("round trip ignored socket deadline: %v", err)
	}
}

func conntrackTestSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestConntrackProbePacket(t *testing.T) {
	for _, test := range []struct {
		source, destination, packet string
	}{
		{"127.0.0.1:1234", "127.0.0.1:5678", "00000000000000000000000008004500001c00000000401100007f0000017f00000104d2162e00080000"},
		{"[::1]:1234", "[::1]:5678", "00000000000000000000000086dd6000000000081140000000000000000000000000000000010000000000000000000000000000000104d2162e00080000"},
	} {
		want, err := hex.DecodeString(test.packet)
		if err != nil {
			t.Fatal(err)
		}
		got := conntrackProbePacket(netip.MustParseAddrPort(test.source), netip.MustParseAddrPort(test.destination))
		if !bytes.Equal(got, want) {
			t.Fatalf("incorrect probe headers: got %x, want %x", got, want)
		}
	}
}

func TestHostConntrackIntegration(t *testing.T) {
	for _, mode := range []string{"untracked", "tracked", "notrack", "zone"} {
		t.Run(mode, func(t *testing.T) {
			withConntrackTestNamespace(t, mode, func() {
				if err := rlimit.RemoveMemlock(); err != nil {
					t.Fatal(err)
				}
				err := probeHostConntrack(t.Context())
				if mode == "tracked" {
					if err != nil {
						t.Fatal(err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), "IPv4") || !strings.Contains(err.Error(), "IPv6") ||
					!strings.Contains(err.Error(), "direction ORIGINAL after UDP round trip: got 0") {
					t.Fatalf("inactive conntrack was not rejected after a successful round trip: %v", err)
				}
			})
		})
	}
}

func withConntrackTestNamespace(t *testing.T, mode string, check func()) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root is required for conntrack namespace probes")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	ns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	defer func() {
		if err := netns.Set(original); err != nil {
			// Do not return a thread in a test namespace to the runtime.
			runtime.LockOSThread()
			t.Errorf("restore network namespace: %v", err)
		}
	}()
	loopback, err := netlink.LinkByIndex(consts.LoopbackIfIndex)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(loopback); err != nil {
		t.Fatal(err)
	}
	if mode != "untracked" {
		var rawExpressions []expr.Any
		switch mode {
		case "notrack":
			rawExpressions = []expr.Any{&expr.Notrack{}}
		case "zone":
			rawExpressions = []expr.Any{
				&expr.Immediate{Register: 1, Data: binary.NativeEndian.AppendUint16(nil, 1)},
				&expr.Ct{Key: expr.CtKeyZONE, Register: 1, SourceRegister: true},
			}
		}
		defer enableConntrackForTest(t, ns, rawExpressions...)()
	}
	check()
}

func enableConntrackForTest(t *testing.T, ns netns.NsHandle, rawExpressions ...expr.Any) func() {
	t.Helper()
	conn, err := nftables.New(nftables.WithNetNSFd(int(ns)))
	if err != nil {
		t.Fatal(err)
	}
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "dae_conntrack_test"})
	chain := conn.AddChain(&nftables.Chain{
		Name: "output", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter,
	})
	conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{&expr.Ct{Key: expr.CtKeySTATE, Register: 1}}})
	if len(rawExpressions) != 0 {
		raw := conn.AddChain(&nftables.Chain{
			Name: "raw_output", Table: table, Type: nftables.ChainTypeFilter,
			Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityRaw,
		})
		conn.AddRule(&nftables.Rule{Table: table, Chain: raw, Exprs: rawExpressions})
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	return func() {
		conn.DelTable(table)
		if err := conn.Flush(); err != nil {
			t.Errorf("remove conntrack fixture: %v", err)
		}
	}
}
