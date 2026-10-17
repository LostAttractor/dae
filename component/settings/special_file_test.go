// SPDX-License-Identifier: AGPL-3.0-only

package settings

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSettingsRejectFIFOWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	link := fifo + ".link"
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, link} {
		// A subprocess makes a blocking-open regression bounded and leak-free.
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSettingsRejectFIFOChild$")
		cmd.Env = append(os.Environ(), "DAE_TEST_SETTINGS_FIFO="+path)
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("settings read failed or blocked: %v\n%s", err, output)
		}
	}
}

func TestSettingsRejectFIFOChild(t *testing.T) {
	path := os.Getenv("DAE_TEST_SETTINGS_FIFO")
	if path == "" {
		t.Skip("subprocess helper")
	}
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("open FIFO: %v", err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	if err := store.Update(func(next *Snapshot) error { next.MITM[macString(mac)] = true; return nil }, nil); err != nil {
		t.Fatal(err)
	}
	store.path = path
	changed, err := store.Reload(func(Snapshot, Snapshot) error { t.Fatal("applied FIFO contents"); return nil })
	if changed || err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("reload FIFO: changed=%t err=%v", changed, err)
	}
	if enabled, exists := store.MITM(mac); !enabled || !exists {
		t.Fatal("failed reload changed accepted state")
	}
}
