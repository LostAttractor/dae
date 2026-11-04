// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/internal/checktime"
)

func TestSlowRecoveryDoesNotDelayFailover(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		primary, backup := new(failoverTransport), new(failoverTransport)
		primary.delay.Store(int64(time.Millisecond))
		backup.delay.Store(int64(20 * time.Millisecond))
		g := failoverGroup(t, testFailoverPolicy(), nil, primary, backup)
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		if g.SelectedDialer(testNetworkType) != g.Dialers[0] {
			t.Fatal("primary was not initially selected")
		}
		// The representative fails twice; every later attempt waits for its
		// deadline. The failed node's recovery must not delay a verified backup.
		primary.blockAfter.Store(primary.attempts.Load() + 2)
		primary.offline.Store(true)
		g.Dialers[0].RequestManualCheck()
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		time.Sleep(time.Until(g.Dialers[0].RuntimeStatus().Recovery.RetryAt) + 10*time.Millisecond)
		synctest.Wait()
		for _, network := range []common.NetworkIndex{common.NetworkTCP4, common.NetworkTCP6} {
			if g.SelectedDialer(network.NetworkType()) != g.Dialers[1] {
				t.Fatalf("%v replacement waited for the failed node's recovery", network)
			}
		}
		if primary.blocked.Load() == 0 || !g.Dialers[0].RuntimeStatus().Checking {
			t.Fatal("fixture did not leave a slow recovery attempt running during failover")
		}
	})
}

// Elections of an unserved network space their rounds by how long it has gone
// unserved, like every other retry, and keep that start across rounds.
func TestUnavailableElectionRoundsFollowDowntime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport := new(failoverTransport)
		transport.offline.Store(true)
		g := failoverGroup(t, testFailoverPolicy(), nil, transport)
		time.Sleep(time.Second)
		synctest.Wait()
		s, network := g.automatic, common.NetworkTCP4
		round := func() (time.Time, time.Duration) {
			ctx, cancel := context.WithCancel(t.Context())
			job := &selectionJob{ctx: ctx, cancel: cancel, replacing: true, force: true}
			s.mu.Lock()
			s.networks[network].job = job
			s.mu.Unlock()
			s.selectNetwork(network, job, nil, false)
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.networks[network].unavailable, time.Until(s.networks[network].retryAt)
		}
		since, _ := round()
		time.Sleep(time.Minute)
		again, delay := round()
		low, high := checktime.Bounds(time.Since(since)/4, g.selectionPolicy.UpgradeIntervalMax)
		if since.IsZero() || again != since || delay < low || delay > high {
			t.Fatalf("election retry in %v after %v unserved, want %v..%v", delay, time.Since(since), low, high)
		}
	})
}
