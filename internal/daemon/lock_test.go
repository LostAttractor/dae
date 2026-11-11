// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDaemonLockExcludesConcurrentStarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dae.lock")
	owner, err := acquireDaemonLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	// No PID file or ready API is needed, including during startup or handoff.
	if other, err := acquireDaemonLock(path); err == nil {
		other.Close()
		t.Fatal("concurrent daemon acquired the lock")
	} else if !strings.Contains(err.Error(), "already running") || !strings.Contains(err.Error(), "dae reload") {
		t.Fatalf("missing reload guidance: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	// An unlocked file left by a stopped daemon is not a running instance.
	next, err := acquireDaemonLock(path)
	if err != nil {
		t.Fatalf("stale lock file blocked startup: %v", err)
	}
	next.Close()
}

func TestStartupRejectsInvalidInheritedDescriptors(t *testing.T) {
	for _, test := range []struct {
		name, resume, probe, message string
	}{
		{name: "conflicting", resume: "3", probe: "4", message: "conflicting"},
		{name: "invalid-exec", resume: "invalid", message: "invalid exec state descriptor"},
		{name: "standard-exec-fd", resume: "2", message: "descriptor"},
		{name: "invalid-preflight", probe: "invalid", message: "invalid preflight descriptor"},
		{name: "wrong-preflight-fd", probe: "3", message: "invalid preflight descriptor"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, name := range []string{replacementEnv, preflightEnv} {
				t.Setenv(name, "")
				if err := os.Unsetenv(name); err != nil {
					t.Fatal(err)
				}
			}
			if test.resume != "" {
				t.Setenv(replacementEnv, test.resume)
			}
			if test.probe != "" {
				t.Setenv(preflightEnv, test.probe)
			}
			startup, err := OpenStartup()
			if startup != nil {
				startup.Close()
			}
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("invalid inherited startup was accepted or misreported: %v", err)
			}
			if _, exists := os.LookupEnv(replacementEnv); exists {
				t.Fatal("exec descriptor remained in the environment")
			}
			if _, exists := os.LookupEnv(preflightEnv); exists {
				t.Fatal("preflight descriptor remained in the environment")
			}
		})
	}
}

func TestDaemonLockOpenFailureIsNotRunningInstance(t *testing.T) {
	_, err := acquireDaemonLock(filepath.Join(t.TempDir(), "missing", "dae.lock"))
	if !errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "already running") {
		t.Fatalf("misreported lock failure: %v", err)
	}
}
