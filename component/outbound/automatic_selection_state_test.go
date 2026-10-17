// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestAutomaticPublicationReleasesSelectionLock(t *testing.T) {
	d := newVerifiedTestDialer(t, "node", "test://publication")
	entered, release := make(chan struct{}), make(chan struct{})
	g := newSelectorTestGroup(t, []*dialer.Dialer{d}, emptyAnnotations(1),
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_MinLastLatency},
		func(available bool, network *common.NetworkType) error {
			if available && network.Index() == common.NetworkTCP4 {
				close(entered)
				<-release
			}
			return nil
		})
	proof, err := d.Check(t.Context(), common.NetworkTCP4, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Release()
	g.automatic.started = true
	committed := make(chan bool, 1)
	go func() { committed <- g.automatic.commit(common.NetworkTCP4, &selectionJob{ctx: t.Context()}, d, proof) }()
	defer close(release)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("election did not reach publication")
	}
	observed := make(chan struct{})
	go func() {
		g.automatic.observe(d, dialer.SelectionForceNone)
		g.automatic.selectedDialer(common.NetworkTCP4)
		close(observed)
	}()
	select {
	case <-observed:
	case <-time.After(time.Second):
		t.Fatal("publication held the selection lock")
	}
	select {
	case <-committed:
		t.Fatal("commit returned before its publication completed")
	default:
	}
}
