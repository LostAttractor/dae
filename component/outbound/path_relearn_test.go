// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// A reload's relearn reaches every pooled path: what it learned unsupported
// becomes discoverable, while its supported modes keep serving.
func TestPathPoolRelearnsPathCapabilities(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := failoverGroup(t, testFailoverPolicy(), nil, new(failoverTransport))
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		d := g.Dialers[0]
		if support := d.RuntimeStatus().SupportState; support[common.NetworkUDP4] != api.NetworkSupportUnsupported {
			t.Fatalf("fixture did not learn UDP as unsupported: %v", support)
		}
		pool := &PathPool{paths: map[string]*dialer.Dialer{"path": d}}
		pool.Relearn()
		if support := d.RuntimeStatus().SupportState; support[common.NetworkUDP4] != api.NetworkSupportUnknown || !d.Usable(common.NetworkTCP4.NetworkType()) {
			t.Fatalf("relearn did not reach the pooled path or took it out of service: %v", support)
		}
	})
}
