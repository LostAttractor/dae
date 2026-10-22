//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package processgroup

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestProcessDescendantCleanup(t *testing.T) {
	g, err := NewPool("descendants-test", 256<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := g.Delete(); err != nil {
			t.Error(err)
		}
	})
	for range 32 {
		p, err := g.Start(exec.Command("sh", "-c", `i=0; while [ "$i" -lt 32 ]; do sleep 60 </dev/null >/dev/null 2>&1 & i=$((i+1)); done; printf 'ready\n'; wait`), 128<<20)
		if err != nil {
			t.Fatal(err)
		}
		ready(t, p)
		results := make([]error, 8)
		var calls sync.WaitGroup
		for i := range results {
			calls.Go(func() { results[i] = p.Close() })
		}
		calls.Wait()
		for _, err := range results {
			if err != nil {
				t.Fatal(err)
			}
		}
		if p.Cmd.ProcessState == nil || p.OOMKilled {
			t.Fatalf("incorrect terminal state: process=%v OOM=%v", p.Cmd.ProcessState, p.OOMKilled)
		}
		if _, err := os.Stat(p.Group.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("worker group remains: %v", err)
		}
	}
}

func ready(t *testing.T, p *Process) {
	t.Helper()
	if err := p.Output.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = p.Close()
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(p.Output).ReadString('\n'); err != nil || line != "ready\n" {
		_ = p.Close()
		t.Fatalf("worker readiness: %q, %v", line, err)
	}
}

func TestStartRollback(t *testing.T) {
	g, err := NewPool("rollback-test", 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := g.Delete(); err != nil {
			t.Error(err)
		}
	})
	for range 32 {
		if _, err := g.Start(exec.Command(filepath.Join(t.TempDir(), "missing")), 64<<20); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("start error: %v", err)
		}
	}
	child, err := create(g.Path, "invalid-limit", -2, g)
	if err == nil || child == nil || !child.Deleted() {
		t.Fatalf("invalid limit rollback: child=%v, err=%v", child, err)
	}
	entries, err := os.ReadDir(g.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Errorf("rollback left %s", entry.Name())
		}
	}
	if err := g.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupRetryOwnership(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission failure requires an unprivileged delegated service")
	}
	g, err := NewPool("retry-test", 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(g.Path, 0700); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error(err)
		}
		if err := g.Delete(); err != nil && !errors.Is(err, ErrCleanup) {
			t.Error(err)
		}
	})
	p, err := g.Start(exec.Command("sh", "-c", "printf 'ready\\n'; exec sleep 60"), 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	ready(t, p)
	if err := os.Chmod(g.Path, 0500); err != nil {
		t.Fatal(err)
	}
	first := p.Close()
	if !errors.Is(first, ErrCleanup) || !errors.Is(g.Check(), ErrCleanup) {
		t.Fatalf("cleanup failure lost: close=%v admission=%v", first, g.Check())
	}
	cmd := exec.Command("sh", "-c", "exit 0")
	if _, err := g.Start(cmd, 64<<20); !errors.Is(err, ErrCleanup) || cmd.Process != nil {
		t.Fatalf("pending cleanup allowed a new worker: %v", err)
	}
	if err := os.Chmod(g.Path, 0700); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !p.Group.Deleted() {
		if time.Until(deadline) <= 0 {
			t.Fatal("cleanup did not finish without another Close")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := g.Check(); err != nil {
		t.Fatalf("recovered pool still unavailable: %v", err)
	}
	if p.Close() != first || !errors.Is(g.CleanupError(), ErrCleanup) {
		t.Fatal("cleanup history or concurrent Close result was lost")
	}
	if err := g.Delete(); !errors.Is(err, ErrCleanup) || !g.Deleted() {
		t.Fatalf("final cleanup did not preserve history and completion: %v", err)
	}
}

func TestKillFailureWithInheritedStderr(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission failure requires an unprivileged delegated service")
	}
	g, err := NewPool("kill-retry-test", 128<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := g.Delete(); err != nil && !errors.Is(err, ErrCleanup) {
			t.Error(err)
		}
	})
	cmd := exec.Command("sh", "-c", `sleep 60 </dev/null >/dev/null & printf 'ready\n'; wait`)
	cmd.Stderr = new(bytes.Buffer)
	p, err := g.Start(cmd, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	killFile := filepath.Join(p.Group.Path, "cgroup.kill")
	t.Cleanup(func() {
		_ = os.Chmod(killFile, 0644)
		_ = p.Group.Kill()
		_ = p.Close()
	})
	ready(t, p)
	if err := os.Chmod(killFile, 0400); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- p.Close() }()
	select {
	case err := <-closed:
		if !errors.Is(err, ErrCleanup) || !errors.Is(g.Check(), ErrCleanup) {
			t.Fatalf("kill failure lost: close=%v admission=%v", err, g.Check())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close stalled on a descendant's inherited stderr")
	}
	if err := os.Chmod(killFile, 0644); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); !p.Group.Deleted(); {
		if time.Until(deadline) <= 0 {
			t.Fatal("failed kill was not retried after permissions recovered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := g.Check(); err != nil {
		t.Fatalf("recovered pool remains blocked: %v", err)
	}
}

func TestPopulatedValidation(t *testing.T) {
	for _, value := range []string{"populated 0\n", "populated 1\n", "populated 2\n", "frozen 0\n", ""} {
		t.Run(value, func(t *testing.T) {
			g := &Group{Path: t.TempDir()}
			if _, err := g.populated(); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing events accepted: %v", err)
			}
			if err := os.WriteFile(filepath.Join(g.Path, "cgroup.events"), []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := g.populated()
			valid := value == "populated 0\n" || value == "populated 1\n"
			if (err == nil) != valid || got != (value == "populated 1\n") {
				t.Fatalf("populated=%v err=%v", got, err)
			}
		})
	}
}
