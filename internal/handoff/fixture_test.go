// SPDX-License-Identifier: AGPL-3.0-only

package handoff

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/okzk/sdnotify"
	"golang.org/x/sys/unix"
)

const fixtureStateEnv = "DAE_EXEC_TEST_STATE_FD"

var (
	fixtureBoot = rand.Text()
	fixtureHeap string
)

type execFixtureState struct {
	Protocol     int
	Generation   int
	PID          int
	Starttime    string
	PreviousBoot string
	Payload      int
	PayloadDev   uint64
	PayloadIno   uint64
	OwnedChild   int
	Args         []string
	Env          []string
}

type execFixtureReport struct {
	Protocol   int
	Generation int
	PID        int
	Starttime  string
	Boot       string
	HeapReset  bool
	Image      string
	Digest     string
	FDs        int
	OwnedChild int
	Args       []string
	Env        []string
}

func fixturePath(name string) string { return filepath.Join(os.Getenv("DAE_EXEC_TEST_DIR"), name) }

func fixtureBaseEnv() []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != fixtureStateEnv {
			env = append(env, entry)
		}
	}
	return env
}

func fixtureStarttime(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	_, fields, ok := strings.CutLast(string(data), ") ")
	if !ok || len(strings.Fields(fields)) < 20 {
		t.Fatalf("invalid process stat: %s", data)
	}
	return strings.Fields(fields)[19]
}

func awaitFixtureFile(ctx context.Context, path string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func fixtureNotify(t *testing.T, message string) {
	t.Helper()
	if os.Getenv("NOTIFY_SOCKET") != "" {
		if err := sdnotify.SdNotify(message); err != nil {
			t.Fatal(err)
		}
	}
}

func fixtureStopped(t *testing.T, signals *Signals) {
	t.Helper()
	if !signals.Stop() {
		t.Fatal("fixture context canceled without a real stop request")
	}
	fixtureNotify(t, "STOPPING=1")
}

// The systemd and unprivileged process tests both drive this real self-exec entry point.
func TestExecFixture(t *testing.T) {
	if os.Getenv("DAE_EXEC_TEST_DIR") == "" {
		t.Skip("subprocess fixture")
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	signals := NewSignals()
	defer signals.Stop()
	if fixtureHeap != "" {
		t.Fatal("old Go heap survived exec")
	}
	fixtureHeap = "old-heap-" + rand.Text()
	state := execFixtureState{Protocol: Protocol, PID: os.Getpid(), Starttime: fixtureStarttime(t), Args: os.Args, Env: fixtureBaseEnv()}
	var payload *os.File
	if value, present := os.LookupEnv(fixtureStateEnv); present {
		fd, err := strconv.Atoi(value)
		if err != nil {
			t.Fatal(err)
		}
		file, err := InheritedFile(fd, "fixture-state")
		if err != nil {
			t.Fatal(err)
		}
		err = ReadState(file, &state)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		if state.Protocol != Protocol || state.PID != os.Getpid() || state.Starttime != fixtureStarttime(t) || state.Generation < 1 || state.Generation > 3 {
			t.Fatalf("invalid inherited fixture state: %+v", state)
		}
		if state.PreviousBoot == fixtureBoot || !reflect.DeepEqual(state.Args, os.Args) || !reflect.DeepEqual(state.Env, fixtureBaseEnv()) {
			t.Fatal("exec did not replace package state or preserve explicit argv/environment")
		}
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", state.OwnedChild)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned child crossed exec: %v", err)
		}
		payload, err = InheritedFile(state.Payload, "fixture-payload")
		if err != nil {
			t.Fatal(err)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(int(payload.Fd()), &stat); err != nil || stat.Dev != state.PayloadDev || stat.Ino != state.PayloadIno {
			t.Fatalf("inherited payload identity mismatch: %v", err)
		}
		flags, err := unix.FcntlInt(payload.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("resumed payload could leak to plugins")
		}
	} else {
		var err error
		payload, err = os.OpenFile(fixturePath("inherited"), os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := payload.WriteString("allowlisted payload"); err != nil {
			t.Fatal(err)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(int(payload.Fd()), &stat); err != nil {
			t.Fatal(err)
		}
		state.Payload, state.PayloadDev, state.PayloadIno = int(payload.Fd()), stat.Dev, stat.Ino
	}
	defer payload.Close()
	data := make([]byte, len("allowlisted payload"))
	if _, err := payload.ReadAt(data, 0); err != nil || string(data) != "allowlisted payload" {
		t.Fatalf("allowlisted payload lost: %q, %v", data, err)
	}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		path, _ := os.Readlink("/proc/self/fd/" + fd.Name())
		if strings.HasPrefix(path, fixturePath("leaked-")) || strings.HasPrefix(path, fixturePath("image-")) {
			t.Fatalf("unlisted descriptor crossed exec: %s", path)
		}
	}
	image, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	elf, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, err = io.Copy(hash, elf)
	elf.Close()
	if err != nil {
		t.Fatal(err)
	}
	report := execFixtureReport{Protocol: Protocol, Generation: state.Generation, PID: os.Getpid(), Starttime: state.Starttime,
		Boot: fixtureBoot, HeapReset: true, Image: image, Digest: fmt.Sprintf("%x", hash.Sum(nil)), FDs: len(fds),
		OwnedChild: state.OwnedChild, Args: os.Args, Env: fixtureBaseEnv()}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	fixtureNotify(t, fmt.Sprintf("READY=1\nSTATUS=generation %d", state.Generation))
	temporary := fixturePath("state.tmp")
	if err := os.WriteFile(temporary, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, fixturePath(fmt.Sprintf("state-%d", state.Generation))); err != nil {
		t.Fatal(err)
	}
	if state.Generation == 3 {
		<-signals.Context().Done()
		fixtureStopped(t, signals)
		return
	}
	if err := awaitFixtureFile(signals.Context(), fixturePath(fmt.Sprintf("next-%d", state.Generation))); err != nil {
		fixtureStopped(t, signals)
		return
	}
	if os.Getenv("NOTIFY_SOCKET") != "" {
		if err := sdnotify.Reloading(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(fixturePath(fmt.Sprintf("reloading-%d", state.Generation)), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := awaitFixtureFile(signals.Context(), fixturePath(fmt.Sprintf("exec-%d", state.Generation))); err != nil {
		fixtureStopped(t, signals)
		return
	}
	child := exec.Command("/proc/self/exe", "-test.run=^TestExecOwnedChildFixture$")
	child.Env = []string{"DAE_EXEC_TEST_OWNED=1"}
	if err := child.Run(); err != nil {
		t.Fatal(err)
	}
	state.OwnedChild = child.Process.Pid
	if err := DrainChildren(signals.Context()); err != nil {
		t.Fatal(err)
	}
	leaked, err := os.Create(fixturePath(fmt.Sprintf("leaked-%d", state.Generation)))
	if err != nil {
		t.Fatal(err)
	}
	defer leaked.Close()
	if _, err := unix.FcntlInt(leaked.Fd(), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	state.Generation++
	state.PreviousBoot = fixtureBoot
	sealed, err := SealState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close()
	target, err := os.Open(fixturePath(fmt.Sprintf("image-%d", min(state.Generation, 2))))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	env := append(fixtureBaseEnv(), fixtureStateEnv+"="+strconv.Itoa(int(sealed.Fd())))
	if signals.Stop() {
		fixtureNotify(t, "STOPPING=1")
		return
	}
	t.Fatal(Exec(target, state.Args, env, []*os.File{payload, sealed}))
}

func TestExecOwnedChildFixture(t *testing.T) {
	if os.Getenv("DAE_EXEC_TEST_OWNED") == "" {
		t.Skip("subprocess fixture")
	}
}

func copyFixtureImages(t *testing.T, dir string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for generation := 1; generation <= 2; generation++ {
		input, err := os.Open(self)
		if err != nil {
			t.Fatal(err)
		}
		output, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("image-%d", generation)), os.O_CREATE|os.O_WRONLY, 0700)
		if err != nil {
			input.Close()
			t.Fatal(err)
		}
		_, copyErr := io.Copy(output, input)
		_, markerErr := fmt.Fprintf(output, "\ndae-exec-generation-%d\n", generation)
		if err := errors.Join(copyErr, markerErr, output.Close(), input.Close()); err != nil {
			t.Fatal(err)
		}
	}
	return self
}

func TestSelfExec(t *testing.T) {
	dir := t.TempDir()
	self := copyFixtureImages(t, dir)
	logFile, err := os.Create(filepath.Join(dir, "fixture.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	command := exec.Command(self, "-test.run=^TestExecFixture$", "--", "fixture argument", "with=equals")
	command.Args[0] = "handoff-fixture-argv0"
	command.Env = []string{"DAE_EXEC_TEST_DIR=" + dir, "DAE_EXEC_TEST_VALUE=kept=value with spaces"}
	command.Stdout, command.Stderr = logFile, logFile
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			<-done
		}
		if t.Failed() {
			data, _ := os.ReadFile(logFile.Name())
			t.Log(string(data))
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var previous execFixtureReport
	for generation := range 4 {
		path := filepath.Join(dir, fmt.Sprintf("state-%d", generation))
		if err := awaitFixtureFile(ctx, path); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var report execFixtureReport
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatal(err)
		}
		if report.Protocol != Protocol || report.Generation != generation || report.PID != command.Process.Pid || !report.HeapReset {
			t.Fatalf("invalid fixture report: %+v", report)
		}
		if !reflect.DeepEqual(report.Args, command.Args) || !reflect.DeepEqual(report.Env, command.Env) {
			t.Fatalf("argv/environment changed: %+v", report)
		}
		if generation > 0 {
			if report.Starttime != previous.Starttime || report.Boot == previous.Boot {
				t.Fatal("PID identity changed or package initialization did not rerun")
			}
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", report.OwnedChild)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("owned child still exists: %v", err)
			}
			image := filepath.Join(dir, fmt.Sprintf("image-%d", min(generation, 2)))
			if report.Image != image {
				t.Fatalf("image=%s, want %s", report.Image, image)
			}
			if generation == 2 && report.Digest == previous.Digest || generation == 3 && report.Digest != previous.Digest {
				t.Fatal("different-ELF or forced same-ELF exec was not exercised")
			}
			if generation > 1 && report.FDs > previous.FDs {
				t.Fatalf("FD count grew: %d -> %d", previous.FDs, report.FDs)
			}
		}
		previous = report
		if generation < 3 {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("next-%d", generation)), nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := awaitFixtureFile(ctx, filepath.Join(dir, fmt.Sprintf("reloading-%d", generation))); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("exec-%d", generation)), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := command.Process.Signal(unix.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		waited = true
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestExecFailureFixture(t *testing.T) {
	if os.Getenv("DAE_EXEC_TEST_FAILURE") == "" {
		t.Skip("subprocess fixture")
	}
	file := rawState(t, "not an ELF", 10, stateSeals)
	allowed, err := SealState(struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()
	leaked, err := os.CreateTemp(t.TempDir(), "leaked")
	if err != nil {
		t.Fatal(err)
	}
	defer leaked.Close()
	if _, err := unix.FcntlInt(leaked.Fd(), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	if err := Exec(file, []string{"fixture-argv0"}, []string{"EXPLICIT=environment"}, []*os.File{allowed}); !errors.Is(err, unix.ENOEXEC) {
		t.Fatalf("exec failure lost its cause: %v", err)
	}
	for _, tc := range []struct {
		file    *os.File
		cloexec bool
	}{{file, true}, {allowed, false}, {leaked, true}} {
		flags, err := unix.FcntlInt(tc.file.Fd(), unix.F_GETFD, 0)
		if err != nil || (flags&unix.FD_CLOEXEC != 0) != tc.cloexec {
			t.Fatalf("CLOEXEC whitelist not applied: %x, %v", flags, err)
		}
	}
}

func TestExecFailure(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), self, "-test.run=^TestExecFailureFixture$")
	command.Env = []string{"DAE_EXEC_TEST_FAILURE=1"}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("exec failure fixture: %v\n%s", err, output)
	}
}
