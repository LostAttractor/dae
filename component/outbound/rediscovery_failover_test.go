// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common"
)

func TestSlowStackRediscoveryDoesNotDelayFailover(t *testing.T) {
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
		// The representative fails twice; every subsequent attempt waits for
		// its deadline. Background discovery must not delay a verified backup.
		primary.blockAfter.Store(primary.attempts.Load() + 2)
		primary.offline.Store(true)
		g.Dialers[0].RequestManualCheck()
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		for _, network := range []common.NetworkIndex{common.NetworkTCP4, common.NetworkTCP6} {
			if g.SelectedDialer(network.NetworkType()) != g.Dialers[1] {
				t.Fatalf("%v replacement waited for the failed node's discovery", network)
			}
		}
		if primary.blocked.Load() == 0 || !g.Dialers[0].RuntimeStatus().Checking {
			t.Fatal("fixture did not leave a slow check running during failover")
		}
	})
}
