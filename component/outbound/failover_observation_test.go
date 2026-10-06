// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestFailoverUsesFreshSameTierSamples(t *testing.T) {
	for _, source := range []string{"explicit", "manual", "shared monitoring"} {
		t.Run(source, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				primary, peer := new(failoverTransport), new(failoverTransport)
				primary.delay.Store(int64(20 * time.Millisecond))
				peer.delay.Store(int64(40 * time.Millisecond))
				g := newFailoverTestGroup(t, testFailoverPolicy(), nil, true, primary, peer)
				time.Sleep(200 * time.Millisecond)
				synctest.Wait()
				if g.SelectedDialer(testNetworkType) != g.Dialers[0] {
					t.Fatal("initial primary was not selected")
				}
				before := peer.attempts.Load()
				before4, before6 := peer.tcp4Attempts.Load(), peer.tcp6Attempts.Load()
				peer.delay.Store(int64(5 * time.Millisecond))
				var owner *DialerGroup
				switch source {
				case "explicit":
					proof, err := g.Dialers[1].Check(t.Context(), common.NetworkTCP4, time.Second)
					if err != nil {
						t.Fatal(err)
					}
					proof.Release()
				case "manual":
					g.Dialers[1].RequestManualCheck()
				case "shared monitoring":
					alias, ok := g.Dialers[1].Share(g.Dialers[1].Property, "monitor")
					if !ok {
						t.Fatal("could not share peer")
					}
					owner = NewDialerGroup(alias.GlobalOption, "monitor", GroupKindSelector, []*dialer.Dialer{alias}, emptyAnnotations(1),
						dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Selector}, nil)
					defer owner.Close()
					start := make(chan struct{})
					if _, err := owner.StartConnectivityChecks(start); err != nil {
						t.Fatal(err)
					}
					close(start)
				}
				time.Sleep(100 * time.Millisecond)
				synctest.Wait()
				if g.SelectedDialer(testNetworkType) != g.Dialers[1] {
					t.Fatal("fresh faster same-tier peer did not replace the primary")
				}
				if got := peer.attempts.Load() - before; got != 2 || peer.tcp4Attempts.Load()-before4 != 1 || peer.tcp6Attempts.Load()-before6 != 1 {
					t.Fatalf("promotion must verify each family once, reusing the triggering result: probes=%d", got)
				}
				if owner != nil {
					_ = owner.Close()
				}
				before = primary.attempts.Load() + peer.attempts.Load()
				time.Sleep(time.Minute)
				synctest.Wait()
				if got := primary.attempts.Load() + peer.attempts.Load(); got != before {
					t.Fatal("sample-driven reselection enabled periodic failover checks")
				}
			})
		})
	}
}

func TestFailoverRechecksCachedPeerBeforeLatencySwitch(t *testing.T) {
	for _, offline := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[offline], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				primary, peer := new(failoverTransport), new(failoverTransport)
				primary.delay.Store(int64(5 * time.Millisecond))
				peer.delay.Store(int64(20 * time.Millisecond))
				g := failoverGroup(t, testFailoverPolicy(), nil, primary, peer)
				time.Sleep(200 * time.Millisecond)
				synctest.Wait()
				before := peer.attempts.Load()
				primary.delay.Store(int64(40 * time.Millisecond))
				peer.delay.Store(int64(30 * time.Millisecond))
				peer.offline.Store(offline)
				g.Dialers[0].RequestManualCheck()
				time.Sleep(45 * time.Millisecond)
				synctest.Wait()
				began := time.Now()
				selected, err := g.Select(testNetworkType)
				if err != nil || selected != g.Dialers[0] || time.Since(began) != 0 {
					t.Fatal("candidate verification interrupted the still-usable primary")
				}
				time.Sleep(100 * time.Millisecond)
				synctest.Wait()
				want := g.Dialers[1]
				checks := int32(2)
				if offline {
					want = g.Dialers[0]
				}
				if g.SelectedDialer(testNetworkType) != want || peer.attempts.Load()-before != checks {
					t.Fatalf("cached peer verification: selected=%v checks=%d, want checks=%d", g.SelectedDialer(testNetworkType), peer.attempts.Load()-before, checks)
				}
			})
		})
	}
}

func TestFailoverObservesRecoveredSameTierPeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		primary, peer := new(failoverTransport), new(failoverTransport)
		primary.delay.Store(int64(20 * time.Millisecond))
		peer.delay.Store(int64(5 * time.Millisecond))
		peer.offline.Store(true)
		policy := testFailoverPolicy()
		g := newFailoverTestGroup(t, policy, nil, true, primary, peer)
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		peer.offline.Store(false)
		g.Dialers[1].RequestManualCheck()
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		status := g.Dialers[1].RuntimeStatus()
		if !status.Healthy || !status.Degraded || !status.CheckEnabled || g.SelectedDialer(testNetworkType) != g.Dialers[0] {
			t.Fatalf("same-tier recovery did not retain a bounded observation window: %+v", status)
		}
		time.Sleep(policy.FailureRecovery)
		synctest.Wait()
		if g.SelectedDialer(testNetworkType) != g.Dialers[1] || g.Dialers[1].RuntimeStatus().Degraded {
			t.Fatal("recovered faster same-tier peer was not selected")
		}
		before := primary.attempts.Load() + peer.attempts.Load()
		time.Sleep(time.Minute)
		synctest.Wait()
		if primary.attempts.Load()+peer.attempts.Load() != before {
			t.Fatal("completed observation enabled periodic failover probes")
		}
	})
}
