// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
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
	"github.com/daeuniverse/dae/pkg/logger"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func replacementLogPipe(t *testing.T) (reader, writer *os.File) {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatal(err)
	}
	reader = os.NewFile(uintptr(fds[0]), "replacement-log-reader")
	writer = os.NewFile(uintptr(fds[1]), "replacement-log-writer")
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	return reader, writer
}

func TestStartupLogMirrorStopsBeforeDaemonWork(t *testing.T) {
	reader, writer := replacementLogPipe(t)
	if err := reader.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	startup := &Startup{logPipe: writer}
	defer startup.closeLogPipe()
	standard := log.StandardLogger()
	oldOutput, oldFormatter, oldLevel := standard.Out, standard.Formatter, standard.Level
	t.Cleanup(func() {
		standard.SetOutput(oldOutput)
		standard.SetFormatter(oldFormatter)
		standard.SetLevel(oldLevel)
	})
	var regular bytes.Buffer
	standard.SetOutput(&regular)
	standard.SetLevel(log.InfoLevel)
	standard.SetFormatter(logger.NewTextFormatter(true))
	startup.MirrorLogs()
	log.WithField("stage", "routing").Info("Preparing control plane")
	startup.ReportInitializationError(errors.New("read settings: denied"))
	log.Info("ordinary daemon log")
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	const line = "level=info msg=Preparing control plane stage=routing\n"
	if string(data) != line+"Initialization failed: read settings: denied\n" || regular.String() != line+"level=info msg=ordinary daemon log\n" {
		t.Fatalf("startup mirror = %q, regular log = %q", data, &regular)
	}
}

func TestStartupErrorThroughExec(t *testing.T) {
	const fixture = "DAE_TEST_STARTUP_ERROR_EXEC"
	failures := map[string]struct {
		message string
		change  func(*replacementManifest)
	}{
		"missing-lock":   {"missing inherited lock", func(*replacementManifest) {}},
		"expired":        {"replacement startup deadline expired", func(m *replacementManifest) { m.Deadline = time.Now().Add(-time.Second) }},
		"future-cutover": {"invalid replacement cutover time", func(m *replacementManifest) { m.CutoverAt = time.Now().Add(time.Minute) }},
	}
	if mode := os.Getenv(fixture); mode != "" {
		failure, ok := failures[mode]
		if !ok {
			t.Fatalf("unknown fixture mode %q", mode)
		}
		if os.Getenv(replacementEnv) != "" {
			if s, err := OpenStartup(); err == nil || !strings.Contains(err.Error(), failure.message) {
				s.Close()
				t.Fatalf("unexpected startup result: %v", err)
			}
			return
		}
		pipe, err := inheritLogPipe(3)
		if err != nil {
			t.Fatal(err)
		}
		defer pipe.Close()
		manifest := replacementManifest{
			Protocol: handoff.Protocol, PID: os.Getpid(), Deadline: time.Now().Add(time.Minute), CutoverAt: time.Now(),
			Operation: api.Operation{ID: "fixture", Kind: "reload", State: "running"}, HostIndex: 1, PeerIndex: 2,
			Files: map[string]int{"logs": int(pipe.Fd())},
		}
		failure.change(&manifest)
		state, err := handoff.SealState(manifest)
		if err != nil {
			t.Fatal(err)
		}
		defer state.Close()
		self, err := os.Open("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		defer self.Close()
		t.Fatal(handoff.Exec(self, os.Args, replacementEnvironment(replacementEnv, int(state.Fd())), []*os.File{state, pipe}))
	}
	for name, failure := range failures {
		t.Run(name, func(t *testing.T) {
			reader, writer := replacementLogPipe(t)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStartupErrorThroughExec$")
			command.Env = append(os.Environ(), fixture+"="+name)
			command.ExtraFiles = []*os.File{writer}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("exec fixture: %v\n%s", err, output)
			}
			_ = writer.Close()
			data, err := io.ReadAll(reader)
			if err != nil || string(data) != "Initialization failed: "+failure.message+"\n" {
				t.Fatalf("startup error = %q, %v", data, err)
			}
		})
	}
}

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
		{name: "protocol", message: "invalid replacement identity", change: func(m *replacementManifest) { m.Protocol++ }},
		{name: "pid", message: "invalid replacement identity", change: func(m *replacementManifest) { m.PID++ }},
		{name: "expired", message: "replacement startup deadline expired", change: func(m *replacementManifest) { m.Deadline = time.Now().Add(-time.Second) }},
		{name: "future-block", message: "invalid replacement cutover time", change: func(m *replacementManifest) { m.CutoverAt = time.Now().Add(time.Hour) }},
		{name: "operation", message: "operation or topology", change: func(m *replacementManifest) { m.Operation.State = "completed" }},
		{name: "topology", message: "operation or topology", change: func(m *replacementManifest) { m.PeerIndex = m.HostIndex }},
		{name: "missing-lock", message: "missing inherited lock", change: func(*replacementManifest) {}},
		{name: "removed-predecessor", message: "invalid inherited resource", change: func(m *replacementManifest) { m.Files["predecessor"] = 3 }},
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
	link0, lockFile := newTemp(), newTemp()
	state := &replacementState{
		files: map[string]*os.File{
			"lock":   lockFile,
			"link/0": link0,
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
	if len(state.files) != 0 {
		t.Fatalf("remaining unconsumed files = %v, want empty", state.files)
	}
}
