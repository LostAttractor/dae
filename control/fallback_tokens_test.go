// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/internal/routingabi"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"golang.org/x/sys/unix"
)

func newFallbackTokenTestMap(t *testing.T, maxEntries uint32) *ebpf.Map {
	t.Helper()
	live, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: maxEntries})
	if errors.Is(err, unix.EPERM) {
		t.Skip("creating an eBPF map requires privileges")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Close() })
	return live
}

func newFallbackTokenTestSequence(t *testing.T) *ebpf.Map {
	t.Helper()
	sequence, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if errors.Is(err, unix.EPERM) {
		t.Skip("creating an eBPF map requires privileges")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sequence.Close() })
	return sequence
}

func TestFallbackTokensFollowTheirGeneration(t *testing.T) {
	live := newFallbackTokenTestMap(t, 2)
	tokens := newFallbackTokens(live, newFallbackTokenTestSequence(t))
	core := &controlPlaneCore{bpf: &BPFState{Runtime: &Runtime{fallbacks: tokens}}}
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
	if token <= routingabi.FALLBACK_TOKEN_RESERVED || value(unavailable, consts.OutboundDirect).Fallback != token || live.Lookup(token, &present) != nil || present != routingabi.FALLBACK_LEASE_LIVE {
		t.Fatal("a generation did not keep one live token across publications")
	}
	if other := tokens.token(netproxy.NewLease(netproxy.NewResourceRef())); other <= routingabi.FALLBACK_TOKEN_RESERVED || other == token {
		t.Fatalf("a second generation reused token %d", other)
	}
	failed := outbound.Connectivity{Network: network, Fallback: netproxy.NewLease(netproxy.NewResourceRef())}
	if full := value(failed, consts.OutboundDirect); full.Fallback != routingabi.FALLBACK_TOKEN_RESERVED {
		t.Fatalf("an untracked generation weakened its policy: %+v", full)
	}
	synctest.Test(t, func(t *testing.T) {
		generation.Abort(errors.New("group recovered"))
		failed.Fallback.Abort(errors.New("group removed"))
		synctest.Wait()
	})
	if !errors.Is(live.Lookup(token, &present), ebpf.ErrKeyNotExist) {
		t.Fatal("an ended generation left its token live")
	}
	if _, tracked := tokens.tokens[failed.Fallback]; tracked {
		t.Fatal("a failed token retained its generation after abort")
	}
	if got := tokens.token(generation); got != routingabi.FALLBACK_TOKEN_RESERVED {
		t.Fatalf("an ended generation received another token: %d", got)
	}
}

func TestFallbackTokensRejectAbortedGeneration(t *testing.T) {
	tokens := newFallbackTokens(newFallbackTokenTestMap(t, 1), newFallbackTokenTestSequence(t))
	synctest.Test(t, func(t *testing.T) {
		generation := netproxy.NewLease(netproxy.NewResourceRef())
		generation.Abort(errors.New("group removed"))
		if got := tokens.token(generation); got != routingabi.FALLBACK_TOKEN_RESERVED {
			t.Fatalf("an already aborted generation received token %d", got)
		}
		if len(tokens.tokens) != 0 {
			t.Fatal("an aborted generation was registered")
		}
	})
}

func TestFallbackTokensFreezePreservesOnlyLiveGenerations(t *testing.T) {
	live := newFallbackTokenTestMap(t, 3)
	tokens := newFallbackTokens(live, newFallbackTokenTestSequence(t))
	synctest.Test(t, func(t *testing.T) {
		revoked := netproxy.NewLease(netproxy.NewResourceRef())
		revokedToken := tokens.token(revoked)
		revoked.Abort(errors.New("group recovered"))
		synctest.Wait()
		var present uint8
		if !errors.Is(live.Lookup(revokedToken, &present), ebpf.ErrKeyNotExist) {
			t.Fatal("an online recovery did not revoke its token")
		}
		pending := netproxy.NewLease(netproxy.NewResourceRef())
		pendingToken := tokens.token(pending)
		survivor := netproxy.NewLease(netproxy.NewResourceRef())
		survivingToken := tokens.token(survivor)
		pending.Abort(errors.New("group removed before freeze"))
		tokens.Freeze()
		survivor.Abort(errors.New("teardown releases group"))
		synctest.Wait()
		tokens.Freeze()
		for _, token := range []uint32{revokedToken, pendingToken} {
			if !errors.Is(live.Lookup(token, &present), ebpf.ErrKeyNotExist) {
				t.Fatalf("freeze revived ended token %d", token)
			}
		}
		if err := live.Lookup(survivingToken, &present); err != nil || present != routingabi.FALLBACK_LEASE_LIVE {
			t.Fatalf("teardown revoked a frozen live token: %v", err)
		}
		if len(tokens.tokens) != 0 {
			t.Fatal("frozen tokens retained aborted generations")
		}
		for _, generation := range []*netproxy.Lease{revoked, pending, survivor, netproxy.NewLease(netproxy.NewResourceRef())} {
			if got := tokens.token(generation); got != routingabi.FALLBACK_TOKEN_RESERVED {
				t.Fatalf("frozen set issued token %d", got)
			}
		}
		if tokens.token(nil) != 0 {
			t.Fatal("freezing changed the keep policy")
		}
	})
}

func TestFallbackTokensFreezeRacesWithAbort(t *testing.T) {
	live := newFallbackTokenTestMap(t, 1)
	sequence := newFallbackTokenTestSequence(t)
	for range 32 {
		tokens := newFallbackTokens(live, sequence)
		generation := netproxy.NewLease(netproxy.NewResourceRef())
		token := tokens.token(generation)
		synctest.Test(t, func(t *testing.T) {
			var wg sync.WaitGroup
			wg.Go(tokens.Freeze)
			wg.Go(func() { generation.Abort(errors.New("group removed")) })
			wg.Wait()
			synctest.Wait()
		})
		var present uint8
		before := live.Lookup(token, &present)
		if before != nil && !errors.Is(before, ebpf.ErrKeyNotExist) {
			t.Fatal(before)
		}
		tokens.Freeze()
		if tokens.token(generation) != routingabi.FALLBACK_TOKEN_RESERVED {
			t.Fatal("a frozen aborted generation was reissued")
		}
		after := live.Lookup(token, &present)
		if (before == nil) != (after == nil) {
			t.Fatal("a completed freeze/abort changed its live set")
		}
		if before == nil {
			if err := live.Delete(token); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestFallbackTokensNeverReuseAcrossRegistries(t *testing.T) {
	sequence := newFallbackTokenTestSequence(t)
	registries := []*fallbackTokens{
		newFallbackTokens(newFallbackTokenTestMap(t, 2), sequence),
		newFallbackTokens(newFallbackTokenTestMap(t, 2), sequence),
	}
	var grants [2][2]uint32
	var wg sync.WaitGroup
	for i, registry := range registries {
		wg.Go(func() {
			for j := range grants[i] {
				grants[i][j] = registry.token(netproxy.NewLease(netproxy.NewResourceRef()))
			}
		})
	}
	wg.Wait()
	seen := make(map[uint32]bool)
	for i, registry := range registries {
		registry.Freeze()
		for _, token := range grants[i] {
			if token <= routingabi.FALLBACK_TOKEN_RESERVED || seen[token] {
				t.Fatalf("registries reused token %d", token)
			}
			seen[token] = true
			var present uint8
			if registry.live.Lookup(token, &present) != nil || present != routingabi.FALLBACK_LEASE_LIVE {
				t.Fatalf("registry lost its live token %d", token)
			}
			if !errors.Is(registries[1-i].live.Lookup(token, &present), ebpf.ErrKeyNotExist) {
				t.Fatalf("another Runtime's live set authorized token %d", token)
			}
		}
	}
	var last uint64
	if err := sequence.Lookup(uint32(0), &last); err != nil || last != 5 {
		t.Fatalf("persistent sequence = %d, error = %v; want 5", last, err)
	}
}

func TestFallbackTokensIssuanceFailsClosed(t *testing.T) {
	for _, failure := range []string{"sequence read", "sequence write", "live map full", "frozen"} {
		t.Run(failure, func(t *testing.T) {
			live := newFallbackTokenTestMap(t, 1)
			sequence := newFallbackTokenTestSequence(t)
			tokens := newFallbackTokens(live, sequence)
			switch failure {
			case "sequence read":
				if err := sequence.Close(); err != nil {
					t.Fatal(err)
				}
			case "sequence write":
				if err := sequence.Freeze(); err != nil {
					t.Fatal(err)
				}
			case "live map full":
				if got := tokens.token(netproxy.NewLease(netproxy.NewResourceRef())); got <= routingabi.FALLBACK_TOKEN_RESERVED {
					t.Fatalf("could not fill the live set: %d", got)
				}
			case "frozen":
				tokens.Freeze()
			}
			generation := netproxy.NewLease(netproxy.NewResourceRef())
			if got := tokens.token(generation); got != routingabi.FALLBACK_TOKEN_RESERVED || tokens.token(generation) != got {
				t.Fatalf("failed generation grant = %d, want the invalid marker", got)
			}
			synctest.Test(t, func(t *testing.T) {
				generation.Abort(errors.New("group removed"))
				synctest.Wait()
			})
			if _, tracked := tokens.tokens[generation]; tracked {
				t.Fatal("a failed token retained its generation after abort")
			}
			if failure != "sequence read" {
				var last uint64
				if err := sequence.Lookup(uint32(0), &last); err != nil {
					t.Fatal(err)
				}
				want := uint64(0)
				if failure == "live map full" {
					want = 3
				}
				if last != want {
					t.Fatalf("sequence = %d, want %d", last, want)
				}
			}
		})
	}
}

func TestFallbackTokensSequenceSkipsMarkersAndNeverWraps(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start uint64
		want  uint32
	}{
		{"empty", 0, 2},
		{"reserved", 1, 2},
		{"last token", uint64(^uint32(0)) - 1, ^uint32(0)},
		{"exhausted", uint64(^uint32(0)), routingabi.FALLBACK_TOKEN_RESERVED},
		{"out of range", uint64(^uint32(0)) + 1, routingabi.FALLBACK_TOKEN_RESERVED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sequence := newFallbackTokenTestSequence(t)
			if err := sequence.Update(uint32(0), tc.start, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			tokens := newFallbackTokens(newFallbackTokenTestMap(t, 1), sequence)
			got := tokens.token(netproxy.NewLease(netproxy.NewResourceRef()))
			if got != tc.want {
				t.Fatalf("after %#x: token = %#x, want %#x", tc.start, got, tc.want)
			}
			wantSequence := tc.start
			if got != routingabi.FALLBACK_TOKEN_RESERVED {
				wantSequence = uint64(got)
			}
			if got == ^uint32(0) && tokens.token(netproxy.NewLease(netproxy.NewResourceRef())) != routingabi.FALLBACK_TOKEN_RESERVED {
				t.Fatal("the last token wrapped to another valid grant")
			}
			var last uint64
			if err := sequence.Lookup(uint32(0), &last); err != nil || last != wantSequence {
				t.Fatalf("sequence = %#x, error = %v; want %#x", last, err, wantSequence)
			}
		})
	}
}
