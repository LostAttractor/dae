// SPDX-License-Identifier: AGPL-3.0-only

package mitmca

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

func TestCARejectsSpecialFiles(t *testing.T) {
	for _, key := range []bool{false, true} {
		for _, symlink := range []bool{false, true} {
			_, certPath, keyPath := testAuthority(t)
			fifo := filepath.Join(t.TempDir(), "fifo")
			if err := unix.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			path := fifo
			if symlink {
				path = fifo + ".link"
				if err := os.Symlink(fifo, path); err != nil {
					t.Fatal(err)
				}
			}
			if key {
				keyPath = path
			} else {
				certPath = path
			}
			// Isolate a blocking regression so the test can kill it cleanly.
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCARejectsSpecialFilesChild$")
			cmd.Env = append(os.Environ(), "DAE_TEST_FIFO_CERT="+certPath, "DAE_TEST_FIFO_KEY="+keyPath)
			output, err := cmd.CombinedOutput()
			cancel()
			if err != nil {
				t.Fatalf("key=%v symlink=%v: loader failed or blocked: %v\n%s", key, symlink, err, output)
			}
		}
	}
}

func TestCARejectsSpecialFilesChild(t *testing.T) {
	cert := os.Getenv("DAE_TEST_FIFO_CERT")
	if cert == "" {
		t.Skip("subprocess helper")
	}
	if _, err := Load(cert, os.Getenv("DAE_TEST_FIFO_KEY")); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected non-regular-file rejection: %v", err)
	}
}
