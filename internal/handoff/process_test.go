// SPDX-License-Identifier: AGPL-3.0-only

package handoff

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func processFixtureCommand(t *testing.T, ctx context.Context, role, dir string) *exec.Cmd {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, self, "-test.run=^TestProcessFixture$")
	command.Env = []string{"DAE_HANDOFF_PROCESS_ROLE=" + role, "DAE_HANDOFF_PROCESS_DIR=" + dir}
	return command
}

func TestChildrenAcrossThreads(t *testing.T) {
	type child struct {
		pid int
		tid int
		err error
	}
	started := make(chan child, 2)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range 2 {
		command := processFixtureCommand(t, t.Context(), "idle", "")
		wg.Go(func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if err := command.Start(); err != nil {
				started <- child{err: err}
				return
			}
			started <- child{pid: command.Process.Pid, tid: unix.Gettid()}
			<-release
			_ = command.Process.Kill()
			_ = command.Wait()
		})
	}
	defer func() { close(release); wg.Wait() }()
	children := []child{<-started, <-started}
	live, err := Children()
	if err != nil {
		t.Fatal(err)
	}
	nonleader := false
	for _, c := range children {
		if c.err != nil {
			t.Fatal(c.err)
		}
		if !live[c.pid] {
			t.Fatalf("thread %d child %d was missed: %v", c.tid, c.pid, live)
		}
		if c.tid != os.Getpid() {
			data, err := os.ReadFile(fmt.Sprintf("/proc/self/task/%d/children", c.tid))
			if err != nil || !strings.Contains(" "+string(data)+" ", " "+strconv.Itoa(c.pid)+" ") {
				t.Fatalf("fixture did not create a nonleader child: %q, %v", data, err)
			}
			nonleader = true
		}
	}
	if !nonleader {
		t.Fatal("fixture did not exercise a nonleader thread")
	}
}

// fork exits after starting branch; branch exits on TERM, leaving its stubborn leaf.
func TestProcessFixture(t *testing.T) {
	role := os.Getenv("DAE_HANDOFF_PROCESS_ROLE")
	if role == "" {
		t.Skip("subprocess fixture")
	}
	dir := os.Getenv("DAE_HANDOFF_PROCESS_DIR")
	writePID := func(name string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	switch role {
	case "idle":
		time.Sleep(time.Minute)
	case "leaf":
		signal.Ignore(unix.SIGTERM)
		writePID("leaf")
		time.Sleep(time.Minute)
	case "branch", "fork":
		childRole, ready := "leaf", "leaf"
		if role == "fork" {
			childRole, ready = "branch", "branch"
		}
		command := processFixtureCommand(t, context.Background(), childRole, dir)
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		if err := awaitFixtureFile(ctx, filepath.Join(dir, ready)); err != nil {
			t.Fatal(err)
		}
		if role == "branch" {
			signals := NewSignals()
			defer signals.Stop()
			writePID("branch")
			<-signals.Context().Done()
		}
	case "drain", "drain-cancel":
		if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = DrainChildren(context.Background()) }()
		if err := drainChildren(ctx, func() (map[int]bool, error) {
			return nil, errors.New("procfs children lists unavailable")
		}); err != nil {
			t.Fatalf("empty child set failed: %v", err)
		}
		command := processFixtureCommand(t, ctx, "fork", dir)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("owned fork: %v\n%s", err, output)
		}
		pids := make(map[string]int)
		for _, name := range []string{"branch", "leaf"} {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(string(data))
			if err != nil {
				t.Fatal(err)
			}
			pids[name] = pid
		}
		live, err := Children()
		if err != nil || !live[pids["branch"]] {
			t.Fatalf("double-fork branch was not adopted: %v, %v", live, err)
		}
		drainCtx := ctx
		if role == "drain-cancel" {
			canceled, stop := context.WithCancel(ctx)
			stop()
			drainCtx = canceled
		}
		started := time.Now()
		err = DrainChildren(drainCtx)
		if err == nil || !strings.Contains(err.Error(), "unexpected descendants") {
			t.Fatalf("residual descendants were accepted: %v", err)
		}
		if time.Since(started) > 4*time.Second {
			t.Fatal("descendant cleanup was not bounded")
		}
		if role == "drain-cancel" {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation cause lost: %v", err)
			}
		}
		for name, pid := range pids {
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s descendant %d not reaped: %v", name, pid, err)
			}
		}
		if err := DrainChildren(ctx); err != nil {
			t.Fatalf("cleanup left children: %v", err)
		}
		var status unix.WaitStatus
		if _, err := unix.Wait4(-1, &status, unix.WNOHANG, nil); !errors.Is(err, unix.ECHILD) {
			t.Fatalf("zombie remained after cleanup: %v", err)
		}
	default:
		t.Fatalf("unknown fixture role %q", role)
	}
}

func TestDrainChildren(t *testing.T) {
	for _, role := range []string{"drain", "drain-cancel"} {
		t.Run(role, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			command := processFixtureCommand(t, ctx, role, t.TempDir())
			command.SysProcAttr = &unix.SysProcAttr{Setpgid: true}
			// Keep timeout cleanup confined to this fixture's own process group.
			command.Cancel = func() error { return unix.Kill(-command.Process.Pid, unix.SIGKILL) }
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("descendant fixture: %v\n%s", err, output)
			}
		})
	}
}
