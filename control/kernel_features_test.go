// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestKernelChecksReportIndependentFailures(t *testing.T) {
	unsupported := errors.New("unsupported")
	err := runKernelChecks(t.Context(),
		kernelCheck{"Netkit", func() error { return unsupported }},
		kernelCheck{"TCX", func() error { return nil }},
		kernelCheck{"bpffs", func() error { return os.ErrPermission }},
	)
	if !errors.Is(err, unsupported) || !errors.Is(err, os.ErrPermission) ||
		!strings.Contains(err.Error(), "Netkit") || !strings.Contains(err.Error(), "bpffs") {
		t.Fatalf("missing named failures: %v", err)
	}
}

func TestKernelChecksStopOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err := runKernelChecks(ctx,
		kernelCheck{"first", func() error { cancel(); return os.ErrPermission }},
		kernelCheck{"second", func() error { t.Fatal("probe ran after cancellation"); return nil }},
	)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("lost cancellation or probe failure: %v", err)
	}
}

func TestKernelFeaturePreflightIntegration(t *testing.T) {
	testKernelFeaturePreflight(t, func() error { return CheckKernelFeatures(t.Context()) })
}

func TestKernelFeaturePreflightVethIntegration(t *testing.T) {
	var usedVeth bool
	testKernelFeaturePreflight(t, func() error {
		return checkKernelFeatures(t.Context(), func(device netlink.Link) error {
			if device.Type() == "netkit" {
				return unix.EOPNOTSUPP
			}
			usedVeth = device.Type() == "veth"
			return netlink.LinkAdd(device)
		})
	})
	if !usedVeth {
		t.Fatal("kernel preflight did not exercise the veth fallback")
	}
}

func testKernelFeaturePreflight(t *testing.T, check func() error) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root is required for kernel feature probes")
	}
	before, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer before.Close()
	// The preflight must neither touch an active dae instance nor leave pins.
	pins, err := os.ReadDir(consts.BpfPinRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := check(); err != nil {
		t.Fatal(err)
	}
	after, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close()
	if !before.Equal(after) {
		t.Fatal("preflight changed the caller's network namespace")
	}
	remaining, err := os.ReadDir(consts.BpfPinRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != len(remaining) {
		t.Fatalf("preflight leaked pinned resources: before=%v after=%v", pins, remaining)
	}
	for i := range pins {
		if pins[i].Name() != remaining[i].Name() {
			t.Fatalf("preflight changed pinned resources: before=%v after=%v", pins, remaining)
		}
	}
}
