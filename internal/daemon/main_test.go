// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/internal/testutil"
)

func TestMain(m *testing.M) {
	testutil.InstallOfflineResolver()
	os.Exit(m.Run())
}

func TestRunRequiresStartupResources(t *testing.T) {
	if err := Run(nil, nil, nil, nil, Options{}); err == nil || !strings.Contains(err.Error(), "startup resources and the instance lock") {
		t.Fatalf("daemon without startup resources was accepted: %v", err)
	}
}

func testStartup(t *testing.T) *Startup {
	t.Helper()
	lock, err := acquireDaemonLock(filepath.Join(t.TempDir(), "dae.lock"))
	if err != nil {
		t.Fatal(err)
	}
	startup := newStartup()
	startup.lock = lock
	t.Cleanup(startup.Close)
	t.Setenv("NOTIFY_SOCKET", "")
	return startup
}
