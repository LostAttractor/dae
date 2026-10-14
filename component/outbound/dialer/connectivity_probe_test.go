// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
)

func TestConnectivityProbesPreserveFailureCause(t *testing.T) {
	for _, selection := range []bool{false, true} {
		name := "background"
		if selection {
			name = "selection"
		}
		t.Run(name, func(t *testing.T) {
			d := newTestDialer(t, testTransport{})
			cause := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ENETUNREACH}
			checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) error {
				return cause
			})
			defer checker.stopRetries()
			var result checkResult
			if selection {
				result = checker.performSelectionCheck(&selectionCheck{ctx: t.Context(), network: common.NetworkTCP4}, 0)
			} else {
				result = checkResult{probes: []probeResult{checker.runProbe(t.Context(), common.NetworkTCP4)}}
			}
			failure := result.failure()
			if !errors.Is(failure, syscall.ENETUNREACH) {
				t.Fatalf("probe discarded its failure cause: %v", failure)
			}
			if operation, ok := errors.AsType[*net.OpError](failure); !ok || operation != cause {
				t.Fatalf("probe discarded its operation metadata: %v", failure)
			}
		})
	}
}

func TestMissingResolverFamilyDoesNotDeclarePathUnsupported(t *testing.T) {
	d := newTestDialer(t, testTransport{})
	d.CheckDnsOptionRaw.Raw = []string{"resolver.example:53", "192.0.2.1"}
	checker := newConnectivityChecker(d.pathRuntime, d.checkDNSConnectivity)
	defer checker.stopRetries()
	probe := checker.runProbe(t.Context(), common.NetworkTCP6)
	if probe.err == nil || !strings.Contains(probe.err.Error(), "no IPv6 address") {
		t.Fatalf("missing resolver family was not reported: %v", probe.err)
	}
	d.applyCheck(checkResult{kind: checkInitial, probes: []probeResult{probe}})
	status := d.RuntimeStatus()
	if status.Healthy || status.SupportState[common.NetworkTCP6] != api.NetworkSupportUnknown {
		t.Fatalf("local resolver configuration changed remote capability: %+v", status)
	}
}
