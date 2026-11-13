// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/internal/handoff"
	"golang.org/x/sys/unix"
)

func TestReplacementPreflightProcess(t *testing.T) {
	if os.Getenv(preflightEnv) == "" {
		t.Skip("real target preflight subprocess fixture")
	}
	startup, err := OpenStartup()
	if err != nil {
		t.Fatal(err)
	}
	defer startup.Close()
	definitions := map[string]plugin.Definition{"fixture": {
		Configure: func(plugin.Spec) (plugin.Factory, error) {
			return func(context.Context, plugin.Services) (plugin.Plugin, error) {
				t.Fatal("lightweight preflight constructed a plugin")
				return nil, nil
			}, nil
		},
		Resources: func(context.Context, plugin.Spec, plugin.Services) (plugin.Resources, error) {
			return plugin.Resources{Plan: new(plugin.Plan)}, nil
		},
		Preflight: func(ctx context.Context, _ plugin.Spec) error {
			path := os.Getenv("DAE_REPLACEMENT_TEST_CONTROL")
			if path == "" {
				return nil
			}
			var dialer net.Dialer
			control, err := dialer.DialContext(ctx, "unix", path)
			if err != nil {
				return err
			}
			defer control.Close()
			stop := context.AfterFunc(ctx, func() { _ = control.Close() })
			defer stop()
			if _, err := control.Write([]byte{1}); err != nil {
				return err
			}
			var release [1]byte
			if _, err := io.ReadFull(control, release[:]); err != nil {
				return err
			}
			return errors.New("fixture preflight rejected")
		},
	}}
	if handled, err := startup.Preflight(os.Getenv("DAE_REPLACEMENT_TEST_CONFIG"), definitions); !handled || err != nil {
		t.Fatalf("real preflight startup failed: handled=%v error=%v", handled, err)
	}
}

func TestReplacementCandidateProcess(t *testing.T) {
	switch os.Getenv("DAE_TEST_REPLACEMENT_PROCESS") {
	case "wait":
		time.Sleep(time.Hour)
	case "exit":
	default:
		t.Skip("candidate subprocess fixture")
	}
}

func TestStopReplacementCandidate(t *testing.T) {
	for _, test := range []struct {
		name   string
		exited bool
		revoke bool
	}{
		{name: "revoke-before-reap", revoke: true},
		{name: "keep-exempt-pid-unreaped"},
		{name: "already-exited", exited: true, revoke: true},
		{name: "exited-exempt-pid-unreaped", exited: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			mode := "wait"
			if test.exited {
				mode = "exit"
			}
			command := exec.Command(os.Args[0], "-test.run=^TestReplacementCandidateProcess$")
			command.Env = append(os.Environ(), "DAE_TEST_REPLACEMENT_PROCESS="+mode)
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = command.Process.Kill()
				if command.ProcessState == nil {
					_ = command.Wait()
				}
			})
			fd, err := unix.PidfdOpen(command.Process.Pid, 0)
			if err != nil {
				t.Fatal(err)
			}
			pidfd := os.NewFile(uintptr(fd), "candidate")
			defer pidfd.Close()
			waitExited := func() {
				t.Helper()
				poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				deadline := time.Now().Add(5 * time.Second)
				for {
					n, err := unix.Poll(poll, int(max(time.Until(deadline).Milliseconds(), 0)))
					if errors.Is(err, unix.EINTR) && time.Now().Before(deadline) {
						continue
					}
					if err != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
						t.Fatalf("preflight did not exit without being reaped: %v %v", poll, err)
					}
					return
				}
			}
			if test.exited {
				waitExited()
			}
			revoked := false
			revokeErr := errors.New("cannot clear candidate exemption")
			err = stopReplacementCandidate(command, func() error {
				if command.ProcessState != nil {
					t.Fatal("candidate reaped before revocation")
				}
				revoked = true
				if !test.revoke {
					return revokeErr
				}
				return nil
			})
			if !revoked {
				t.Fatal("candidate exemption was not revoked")
			}
			if !test.revoke {
				if !errors.Is(err, revokeErr) || command.ProcessState != nil {
					t.Fatalf("failed revocation reaped candidate: state=%v err=%v", command.ProcessState, err)
				}
				waitExited()
			} else if err != nil || command.ProcessState == nil {
				t.Fatalf("successful revocation did not reap candidate: state=%v err=%v", command.ProcessState, err)
			}
		})
	}
}

func TestReadReplacementRejectsInvalidState(t *testing.T) {
	for _, test := range []struct {
		name, message string
		change        func(*replacementManifest)
	}{
		{name: "protocol", message: "identity or deadline", change: func(m *replacementManifest) { m.Protocol++ }},
		{name: "pid", message: "identity or deadline", change: func(m *replacementManifest) { m.PID++ }},
		{name: "expired", message: "identity or deadline", change: func(m *replacementManifest) { m.Deadline = time.Now().Add(-time.Second) }},
		{name: "future-block", message: "identity or deadline", change: func(m *replacementManifest) { m.CutoverAt = time.Now().Add(time.Hour) }},
		{name: "operation", message: "operation or topology", change: func(m *replacementManifest) { m.Operation.State = "completed" }},
		{name: "topology", message: "operation or topology", change: func(m *replacementManifest) { m.PeerIndex = m.HostIndex }},
		{name: "missing-lock", message: "missing inherited lock", change: func(*replacementManifest) {}},
		{name: "removed-predecessor", message: "invalid inherited resource", change: func(m *replacementManifest) { m.Files["predecessor"] = 3 }},
		{name: "invalid-observe-port", message: "invalid inherited resource", change: func(m *replacementManifest) { m.Files["observe/0"] = 3 }},
		{name: "standard-resource-fd", message: "invalid lock descriptor", change: func(m *replacementManifest) { m.Files["lock"] = 2 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := replacementManifest{
				Protocol: handoff.Protocol, PID: os.Getpid(), Deadline: time.Now().Add(time.Minute), CutoverAt: time.Now().Add(-time.Second),
				Operation: api.Operation{ID: "fixture", Kind: "reload", State: "running"}, HostIndex: 1, PeerIndex: 2, Files: make(map[string]int),
			}
			test.change(&manifest)
			file, err := handoff.SealState(manifest)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 3)
			if err != nil {
				t.Fatal(err)
			}
			state, err := readReplacement(strconv.Itoa(fd))
			if state != nil {
				state.close()
			}
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("invalid replacement state was accepted or misreported: %v", err)
			}
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Fatalf("rejected manifest leaked its descriptor: %v", err)
			}
		})
	}
}

func TestStopReplacementCandidateBeforeStart(t *testing.T) {
	command := exec.Command("/nonexistent/dae-replacement")
	if err := command.Start(); err == nil {
		t.Fatal("unexpected candidate start")
	}
	if err := stopReplacementCandidate(command, nil); err != nil {
		t.Fatalf("failed start cannot be cleaned up: %v", err)
	}
}

func TestReplacementStateTakeTransfersAndCleansOwnership(t *testing.T) {
	newTemp := func() *os.File {
		f, err := os.CreateTemp(t.TempDir(), "take")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	obsGood, obsBad, link0, lockFile := newTemp(), newTemp(), newTemp(), newTemp()
	state := &replacementState{
		files: map[string]*os.File{
			"lock":          lockFile,
			"link/0":        link0,
			"observe/9090":  obsGood,
			"observe/99999": obsBad,
		},
	}
	if got := state.take("lock"); got != lockFile {
		t.Fatalf("take(lock) = %v, want %v", got, lockFile)
	}
	if state.take("lock") != nil {
		t.Fatal("second take(lock) returned non-nil")
	}
	if _, err := state.takeLinks(2); err == nil {
		t.Fatal("takeLinks(2) with missing link/1 succeeded")
	}
	if _, err := link0.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("takeLinks failure leaked link/0 FD: %v", err)
	}
	if _, err := state.takeObservability(); err == nil {
		t.Fatal("takeObservability with out-of-range port succeeded")
	}
	for name, file := range map[string]*os.File{"obsGood": obsGood, "obsBad": obsBad} {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("%s leaked on takeObservability error: %v", name, err)
		}
	}
	if len(state.files) != 0 {
		t.Fatalf("remaining unconsumed files = %v, want empty", state.files)
	}
}
