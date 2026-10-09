// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/netutils"
	"golang.org/x/sys/unix"
)

func TestKernelPreflightBeforeStartupResources(t *testing.T) {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var capabilities [2]unix.CapUserData
	if err := unix.Capget(&header, &capabilities[0]); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 || capabilities[0].Effective != 0 || capabilities[1].Effective != 0 {
		t.Skip("this test needs an unprivileged process to reject kernel probes")
	}
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	conf := mitmConfigForTest(t, "")
	err := Run(conf, nil, nil, &netutils.InternalResolver{}, Options{ConfigFile: filepath.Join(dir, "config.dae")})
	if err == nil || !strings.Contains(err.Error(), "kernel preflight") {
		t.Fatalf("startup did not reject kernel prerequisites first: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("kernel preflight failure prepared startup resources: %v %v", entries, err)
	}
}
