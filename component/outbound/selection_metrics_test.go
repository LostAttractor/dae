// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func selectionMetric(t *testing.T, g *DialerGroup, d *dialer.Dialer, network common.NetworkIndex) stats.SelectionMetrics {
	t.Helper()
	path := d.StatsPath(g.Name, network.NetworkType())
	for _, metric := range g.SelectionMetrics() {
		if metric.Path == path {
			return metric
		}
	}
	t.Fatalf("no selection metric for %+v", path)
	return stats.SelectionMetrics{}
}

func TestSelectionMetricsUseStatusMeasurementsForEveryPolicy(t *testing.T) {
	for _, policy := range []consts.DialerSelectionPolicy{
		consts.DialerSelectionPolicy_Fixed, consts.DialerSelectionPolicy_Selector,
		consts.DialerSelectionPolicy_MinLastLatency,
	} {
		t.Run(string(policy), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				transport := new(failoverTransport)
				transport.delay.Store(int64(20 * time.Millisecond))
				selection := testFailoverPolicy()
				selection.Policy = policy
				annotations := []*dialer.Annotation{{AddLatency: -time.Second}}
				g := newFailoverTestGroup(t, selection, annotations, false, transport)
				d := g.Dialers[0]
				time.Sleep(300 * time.Millisecond)
				synctest.Wait()

				runtime := d.RuntimeStatus()
				metric := selectionMetric(t, g, d, common.NetworkTCP4)
				if !runtime.Healthy || !runtime.HasLatency || !metric.HasLatency || metric.Latency != runtime.Latency || metric.Latency.Last <= 0 {
					t.Fatalf("metrics and status disagree: metric=%+v runtime=%+v", metric, runtime)
				}
				if automatic := selection.Automatic(); metric.HasScore != automatic || metric.Ranked != automatic {
					t.Fatalf("policy %s has unexpected score/rank: %+v", policy, metric)
				}
				if metric.HasScore {
					status := g.NodeSelectionStatus(d, runtime)
					if metric.Score != status.Score || metric.Score >= 0 || metric.Rank != 0 {
						t.Fatalf("selection score differs from status or changes measured latency: metric=%+v status=%+v", metric, status)
					}
				}

				transport.offline.Store(true)
				d.ReportDataPlaneError(errors.New("path failed"))
				time.Sleep(200 * time.Millisecond)
				synctest.Wait()
				if d.RuntimeStatus().Healthy {
					t.Fatal("fixture did not lose connectivity")
				}
				for _, metric := range g.SelectionMetrics() {
					if metric.Ranked {
						t.Fatalf("failed path retained a rank: %+v", metric)
					}
				}
				_ = g.Close()
				if got := g.SelectionMetrics(); len(got) != 0 {
					t.Fatalf("closed group published metrics: %+v", got)
				}
			})
		})
	}
}
