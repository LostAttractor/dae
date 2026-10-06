// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestSelectedNetworkDoesNotResumeFromAnotherNetworksProof(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := new(failoverTransport)
		transport.delay.Store(int64(time.Millisecond))
		g := failoverGroup(t, testFailoverPolicy(), nil, transport)
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		// Freeze elections to observe admission of the existing selections while
		// independent real checks update the shared worker's health and proofs.
		g.automatic.cancel()
		g.automatic.wg.Wait()
		transport.ipv6Offline.Store(true)
		d := g.Dialers[0]
		failed, err := d.Check(t.Context(), common.NetworkTCP6, time.Second)
		failed.Release()
		if err == nil {
			t.Fatal("IPv6 failure was not observed")
		}
		proof, err := d.Check(t.Context(), common.NetworkTCP4, time.Second)
		defer proof.Release()
		if err != nil {
			t.Fatal(err)
		}
		if selected, err := g.Select(common.NetworkTCP4.NetworkType()); err != nil || selected != d {
			t.Fatalf("verified IPv4 did not resume: %v", err)
		}
		if selected, err := g.Select(common.NetworkTCP6.NetworkType()); selected != nil || !errors.Is(err, ErrNoAliveDialer) {
			t.Fatal("old IPv6 selection resumed using only IPv4 recovery")
		}
	})
}

func TestFreshCurrentSampleConsidersDormantPeer(t *testing.T) {
	for _, recreate := range []bool{false, true} {
		t.Run(map[bool]string{false: "awake", true: "dormant"}[recreate], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				primary, peer := new(failoverTransport), new(failoverTransport)
				primary.delay.Store(int64(5 * time.Millisecond))
				peer.delay.Store(int64(20 * time.Millisecond))
				g := newFailoverTestGroup(t, testFailoverPolicy(), nil, recreate, primary, peer)
				time.Sleep(200 * time.Millisecond)
				synctest.Wait()
				if g.SelectedDialer(testNetworkType) != g.Dialers[0] {
					t.Fatal("fixture failed to select the faster primary")
				}
				if recreate && !g.Dialers[1].RuntimeStatus().Dormant {
					t.Fatal("fixture failed to release the idle peer")
				}
				before := peer.attempts.Load()
				primary.delay.Store(int64(40 * time.Millisecond))
				peer.delay.Store(int64(30 * time.Millisecond))
				g.Dialers[0].RequestManualCheck()
				time.Sleep(500 * time.Millisecond)
				synctest.Wait()
				if g.SelectedDialer(testNetworkType) != g.Dialers[1] {
					t.Fatalf("fresh 40ms primary did not verify/promote the formerly 20ms peer: additional peer probes=%d dormant=%v", peer.attempts.Load()-before, g.Dialers[1].RuntimeStatus().Dormant)
				}
				before = primary.attempts.Load() + peer.attempts.Load()
				time.Sleep(time.Minute)
				synctest.Wait()
				if primary.attempts.Load()+peer.attempts.Load() != before {
					t.Fatal("sample-driven standby verification enabled periodic probes")
				}
			})
		})
	}
}

func TestSelectionBudgetDoesNotStarveLowerDegradedTier(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		highest, high, middle, fallback := new(failoverTransport), new(failoverTransport), new(failoverTransport), new(failoverTransport)
		transports := []*failoverTransport{highest, high, middle, fallback}
		annotations := make([]*dialer.Annotation, len(transports))
		for i, transport := range transports {
			transport.offline.Store(true)
			annotations[i] = &dialer.Annotation{Priority: len(transports) - i}
		}
		policy := testFailoverPolicy()
		policy.SelectionTimeout = 200 * time.Millisecond
		g := failoverGroup(t, policy, annotations, transports...)
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		for _, d := range g.Dialers {
			if !d.RuntimeStatus().Degraded {
				t.Fatal("fixture did not confirm the initial outage on every node")
			}
		}
		for _, transport := range transports[:3] {
			transport.delay.Store(int64(time.Hour))
		}
		before := fallback.attempts.Load()
		fallback.offline.Store(false)
		time.Sleep(20 * time.Second)
		synctest.Wait()
		if g.SelectedDialer(testNetworkType) != g.Dialers[3] {
			t.Fatalf("available fallback starved across repeated bounded rounds: additional fallback probes=%d", fallback.attempts.Load()-before)
		}
	})
}

func TestDormantCandidateRejectionContinuesToNextPeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		primary, first, next := new(failoverTransport), new(failoverTransport), new(failoverTransport)
		primary.delay.Store(int64(5 * time.Millisecond))
		first.delay.Store(int64(20 * time.Millisecond))
		next.delay.Store(int64(25 * time.Millisecond))
		g := newFailoverTestGroup(t, testFailoverPolicy(), nil, true, primary, first, next)
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		primary.delay.Store(int64(40 * time.Millisecond))
		first.delay.Store(int64(60 * time.Millisecond))
		next.delay.Store(int64(30 * time.Millisecond))
		g.Dialers[0].RequestManualCheck()
		time.Sleep(time.Second)
		synctest.Wait()
		if g.SelectedDialer(testNetworkType) != g.Dialers[2] {
			t.Fatal("rejecting a stale faster sample hid the next dormant peer")
		}
		before := primary.attempts.Load() + first.attempts.Load() + next.attempts.Load()
		time.Sleep(time.Minute)
		synctest.Wait()
		if primary.attempts.Load()+first.attempts.Load()+next.attempts.Load() != before {
			t.Fatal("rejected standby kept triggering checks without new samples")
		}
	})
}
