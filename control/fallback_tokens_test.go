// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"testing"
	"testing/synctest"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"golang.org/x/sys/unix"
)

func TestFallbackTokensFollowTheirGeneration(t *testing.T) {
	live, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 2})
	if errors.Is(err, unix.EPERM) {
		t.Skip("creating an eBPF map requires privileges")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	// Pinned flows outlive the process: a restart must not reissue its tokens.
	if newFallbackTokens(live).next == newFallbackTokens(live).next {
		t.Fatal("token allocation does not start at a random point")
	}
	core := &controlPlaneCore{bpf: &BPFState{Runtime: &Runtime{fallbacks: newFallbackTokens(live)}}}
	generation := netproxy.NewLease(netproxy.NewResourceRef())
	network := common.NetworkTCP4.NetworkType()
	value := func(update outbound.Connectivity, behavior consts.OutboundIndex) bpfOutboundConnectivity {
		return core.outboundConnectivityValue(update, false, behavior)
	}
	unavailable := outbound.Connectivity{Network: network, Fallback: generation}
	if value(outbound.Connectivity{Network: network}, consts.OutboundDirect).Fallback != 0 ||
		value(unavailable, consts.OutboundBlock).Fallback != 0 ||
		value(outbound.Connectivity{Network: network, Available: true, Fallback: generation}, consts.OutboundDirect).Fallback != 0 {
		t.Fatal("only an interruptible direct fallback may carry a token")
	}
	token := value(unavailable, consts.OutboundDirect).Fallback
	var present uint8
	if token == 0 || value(unavailable, consts.OutboundDirect).Fallback != token || live.Lookup(token, &present) != nil {
		t.Fatal("a generation did not keep one live token across publications")
	}
	if other := core.bpf.fallbacks.token(netproxy.NewLease(netproxy.NewResourceRef())); other == 0 || other == token {
		t.Fatalf("a second generation reused token %d", other)
	}
	if full := core.bpf.fallbacks.token(netproxy.NewLease(netproxy.NewResourceRef())); full != 0 {
		t.Fatalf("an untracked generation received token %d instead of the uninterruptible zero", full)
	}
	synctest.Test(t, func(t *testing.T) {
		generation.Abort(errors.New("group recovered"))
		synctest.Wait()
	})
	if !errors.Is(live.Lookup(token, &present), ebpf.ErrKeyNotExist) {
		t.Fatal("an ended generation left its token live")
	}
}

// Flow state shares the token field with markers at zero and the reserved value.
func TestFallbackTokensSkipFlowMarkers(t *testing.T) {
	live, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 2})
	if errors.Is(err, unix.EPERM) {
		t.Skip("creating an eBPF map requires privileges")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	for _, start := range []uint32{0, ^uint32(0) - 1, ^uint32(0)} {
		tokens := newFallbackTokens(live)
		tokens.next = start
		want := uint32(2)
		if start == ^uint32(0)-1 {
			want = ^uint32(0)
		}
		got := tokens.token(netproxy.NewLease(netproxy.NewResourceRef()))
		if got != want {
			t.Fatalf("after %#x: token = %#x, want %#x", start, got, want)
		}
		if err := live.Delete(got); err != nil {
			t.Fatal(err)
		}
	}
}
