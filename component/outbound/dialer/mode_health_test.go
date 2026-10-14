// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/netproxy"
)

func modeCheckResult(d *Dialer, kind checkKind, probes ...probeResult) checkResult {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return checkResult{kind: kind, generation: d.failures.generation, modeGenerations: d.modeGenerationsLocked(), readiness: d.sessionSnapshot().ReadinessVersion, probes: probes}
}

func allModeProbes() []probeResult {
	var probes []probeResult
	for network := range common.NetworkIndex(common.NetworkTypeCount) {
		probes = append(probes, probeResult{network: network, latency: time.Duration(network+1) * time.Millisecond})
	}
	return probes
}

func TestModeFailurePreservesSiblingProofLatencyAndPriority(t *testing.T) {
	for failed := range common.NetworkIndex(common.NetworkTypeCount) {
		t.Run(failed.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newTestDialer(t, testTransport{})
				d.group.failureRecovery = time.Second
				d.applyCheck(modeCheckResult(d, checkInitial, allModeProbes()...))
				var before [common.NetworkTypeCount]SelectionSnapshot
				for i := range before {
					before[i] = d.SelectionSnapshot(common.NetworkIndex(i).NetworkType())
				}
				stale := modeCheckResult(d, checkHealth, allModeProbes()...)
				d.ReportNetworkError(failed, errors.New("upstream timeout"))
				d.applyCheck(stale)
				if d.ProofValid(before[failed].Proof) || !d.VerifiedUsable(failed.NetworkType()) {
					t.Fatal("confirmation did not preserve admission while invalidating old evidence")
				}
				d.applyCheck(modeCheckResult(d, checkHealth, probeResult{network: failed, err: errors.New("mode unavailable")}))
				for network := range common.NetworkIndex(common.NetworkTypeCount) {
					snapshot := d.SelectionSnapshot(network.NetworkType())
					if snapshot.Support != api.NetworkSupportConfirmed {
						t.Fatalf("temporary failure changed %s capability", network)
					}
					if network == failed {
						if snapshot.Usable || !snapshot.Degraded || d.VerifiedUsable(network.NetworkType()) {
							t.Fatalf("failed mode retained admission: %+v", snapshot)
						}
					} else if !snapshot.Usable || snapshot.Degraded || !d.ProofValid(before[network].Proof) || snapshot.Latency != before[network].Latency {
						t.Fatalf("%s failure contaminated %s: %+v", failed, network, snapshot)
					}
				}
				if !d.RuntimeStatus().Healthy {
					t.Fatal("partial outage hid healthy modes")
				}
				recover := func() {
					d.applyCheck(modeCheckResult(d, checkHealth, probeResult{network: failed, latency: time.Millisecond}))
				}
				recover()
				if !d.SelectionSnapshot(failed.NetworkType()).Degraded {
					t.Fatal("one success bypassed the affected mode's recovery window")
				}
				time.Sleep(time.Second)
				recover()
				if snapshot := d.SelectionSnapshot(failed.NetworkType()); !snapshot.Usable || snapshot.Degraded {
					t.Fatalf("completed recovery did not restore mode: %+v", snapshot)
				}
			})
		})
	}
}

func TestSharedSessionReplacementRequiresEachModeProof(t *testing.T) {
	transport := newTestSessionTransport(netproxy.SessionConnected)
	d := newTestDialer(t, transport)
	d.applyCheck(modeCheckResult(d, checkInitial, allModeProbes()...))
	old := d.SelectionSnapshot(common.NetworkTCP6.NetworkType()).Proof
	transport.state.Transition(netproxy.SessionDisconnected, errors.New("shared session lost"))
	d.applySessionState(transport.Snapshot())
	for network := range common.NetworkIndex(common.NetworkTypeCount) {
		if d.Usable(network.NetworkType()) {
			t.Fatalf("%s survived shared session failure", network)
		}
	}
	transport.state.Transition(netproxy.SessionConnected, nil)
	d.applySessionState(transport.Snapshot())
	d.applyCheck(modeCheckResult(d, checkSelection, probeResult{network: common.NetworkTCP4}))
	for network := range common.NetworkIndex(common.NetworkTypeCount) {
		if got := d.Usable(network.NetworkType()); got != (network == common.NetworkTCP4) {
			t.Fatalf("new session %s usability = %v", network, got)
		}
	}
	if d.ProofValid(old) {
		t.Fatal("session replacement revived an old proof")
	}
}

func TestSharedRecoveryRequiresFreshAppliedSuccess(t *testing.T) {
	for _, scenario := range []string{"failed", "empty", "stale mode", "stale shared", "stale success and fresh failure"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newTestDialer(t, testTransport{})
				d.group.failureRecovery = time.Second
				d.applyCheck(modeCheckResult(d, checkInitial, allModeProbes()...))
				sharedFailure := modeCheckResult(d, checkHealth)
				sharedFailure.connectErr = errors.New("shared transport lost")
				d.applyCheck(sharedFailure)
				d.applyCheck(modeCheckResult(d, checkHealth, probeResult{network: common.NetworkTCP4}))
				before := d.SelectionSnapshot(common.NetworkTCP4.NetworkType())
				if !before.Usable || !before.Degraded || before.RecoveryElapsed != 0 {
					t.Fatalf("first success did not start shared recovery: %+v", before)
				}
				since, verified := d.failures.recoverySince, d.failures.recoveryVerifiedAt
				result := modeCheckResult(d, checkHealth, probeResult{network: common.NetworkTCP6, err: errors.New("IPv6 unavailable")})
				switch scenario {
				case "empty":
					result.probes = nil
				case "stale mode", "stale success and fresh failure":
					result.probes[0].err = nil
					d.applyCheck(modeCheckResult(d, checkHealth, probeResult{network: common.NetworkTCP6, err: errors.New("newer IPv6 failure")}))
					if scenario == "stale success and fresh failure" {
						result.probes = append(result.probes, probeResult{network: common.NetworkUDP6, err: errors.New("UDP unavailable")})
					}
				case "stale shared":
					result.probes[0].err = nil
					result.generation--
				}
				time.Sleep(time.Second)
				d.applyCheck(result)
				after := d.SelectionSnapshot(common.NetworkTCP4.NetworkType())
				if !after.Usable || !after.Degraded || after.RecoveryElapsed != 0 || d.group.recovered || d.failures.recoverySince != since || d.failures.recoveryVerifiedAt != verified {
					t.Fatalf("check without fresh successful evidence advanced shared recovery: %+v", after)
				}
				d.applyCheck(modeCheckResult(d, checkHealth,
					probeResult{network: common.NetworkTCP4},
					probeResult{network: common.NetworkTCP6, err: errors.New("IPv6 still unavailable")},
				))
				if snapshot := d.SelectionSnapshot(common.NetworkTCP4.NetworkType()); !snapshot.Usable || snapshot.Degraded {
					t.Fatalf("fresh successful probe did not complete shared recovery: %+v", snapshot)
				}
				if d.Usable(common.NetworkTCP6.NetworkType()) {
					t.Fatal("shared recovery restored a failed mode")
				}
			})
		})
	}
}

func TestAuthenticationFailureBlocksSuccessfulSiblingProbes(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.applyCheck(modeCheckResult(d, checkInitial, allModeProbes()...))
	probes := allModeProbes()
	probes[common.NetworkUDP6].err = netproxy.WrapFailure(errors.New("bad credentials"), netproxy.Failure{Reason: netproxy.ReasonAuth, Origin: netproxy.OriginPeer, Scope: netproxy.ScopeStream})
	result, accepted := d.applyCheck(modeCheckResult(d, checkHealth, probes...))
	if !accepted || result.success || d.RuntimeStatus().Healthy {
		t.Fatal("successful sibling probes hid authentication failure")
	}
	for network := range common.NetworkIndex(common.NetworkTypeCount) {
		if d.Usable(network.NetworkType()) || d.ProofValid(d.SelectionSnapshot(network.NetworkType()).Proof) {
			t.Fatalf("%s ignored shared authentication failure", network)
		}
	}
}
