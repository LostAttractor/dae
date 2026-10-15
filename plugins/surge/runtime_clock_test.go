// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"testing"
	"testing/synctest"
)

// Subprocess pipes are not durably blocked in synctest, so the fake clock
// cannot advance while a Node worker is alive. Scheduler timing is tested
// in-process; Node cancellation and task execution use real-time tests.
func runtimeFakeClockTest(t *testing.T, test func(*testing.T)) {
	t.Helper()
	if compiledJSRuntime == "nodejs" {
		t.Skip("fake-clock test requires an in-process runtime")
	}
	synctest.Test(t, test)
}
