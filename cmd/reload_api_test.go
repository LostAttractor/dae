// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"bufio"
	"bytes"
	"context"
	"debug/elf"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/internal/handoff"
	"github.com/daeuniverse/dae/internal/testutil"
	"golang.org/x/sys/unix"
)

func TestReloadCommandsUseConfiguredAPI(t *testing.T) {
	for _, kind := range []string{"reload", "suspend"} {
		for _, explicit := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/environment", true: "/flag"}[explicit], func(t *testing.T) {
				t.Setenv("DAE_API_KEY", "command-test-key")
				requests := 0
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests++
					if r.Header.Get("Authorization") != "Bearer command-test-key" {
						t.Error("missing configured API credential")
					}
					switch r.Method + " " + r.URL.Path {
					case "POST /api/operations":
						var request api.OperationRequest
						if err := json.UnmarshalRead(r.Body, &request); err != nil {
							t.Error(err)
						}
						if request.Kind != kind || !request.Abort || r.Header.Get(api.ReloadLogFDHeader) != "" || request.ExecutablePID != 0 || request.ExecutableFD != 0 {
							t.Errorf("operation request = %+v", request)
						}
						w.WriteHeader(http.StatusAccepted)
						_ = json.MarshalWrite(w, api.Operation{ID: "mine", Kind: kind, State: "queued"})
					case "GET /api/operations/mine":
						_ = json.MarshalWrite(w, api.Operation{ID: "mine", Kind: kind, State: "completed", Result: "finished"})
					default:
						t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer server.Close()
				t.Setenv("DAE_API_CA", testutil.TLSFile(t, server))
				t.Setenv("DAE_API_ENDPOINT", server.URL)
				args := []string{"--abort"}
				if explicit {
					t.Setenv("DAE_API_ENDPOINT", "unix:///unused/dae.sock")
					args = append(args, "--api", server.URL)
				}
				command := newReloadCommand(kind == "suspend")
				var output bytes.Buffer
				command.SetOut(&output)
				command.SetErr(&output)
				command.SetArgs(args)
				if err := command.ExecuteContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				if requests != 2 || !strings.Contains(output.String(), "finished") {
					t.Fatalf("requests=%d, output=%q", requests, output.String())
				}
			})
		}
	}
}

func unixReloadTestEndpoint(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dae.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	return "unix://" + path
}

func TestBinaryReloadElevatesBeforeOpeningCandidate(t *testing.T) {
	const child = "DAE_TEST_RELOAD_ELEVATION"
	const relative = "current/../release/dae"
	if os.Getenv(child) == "1" {
		command := newReloadCommand(false)
		command.SetArgs([]string{"--abort", "--binary", relative})
		t.Fatal(command.ExecuteContext(t.Context())) // The helper exits the CLI.
	}
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged caller")
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "dae.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "sudo")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(helper, 0755); err != nil {
		t.Fatal(err)
	}
	endpoint := "unix://" + socket
	t.Setenv(child, "1")
	t.Setenv("PATH", dir)
	t.Setenv("DAE_API_ENDPOINT", endpoint)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), self, "-test.run=^TestBinaryReloadElevatesBeforeOpeningCandidate$")
	command.Dir = dir
	output, err := command.CombinedOutput()
	want := self + "\nreload\n--abort=true\n--api=" + endpoint + "\n--binary=" + dir + "/" + relative + "\n"
	if err != nil || !strings.HasSuffix(string(output), want) {
		t.Fatalf("elevation args = %q, %v; want suffix %q", output, err, want)
	}
}

func TestLocalReloadShowsLogsBeforeAPIResumes(t *testing.T) {
	logs, stderr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer logs.Close()
	defer stderr.Close()
	candidate := filepath.Join(t.TempDir(), "new-dae")
	const selectedImage = elf.ELFMAG + "selected"
	if err := os.WriteFile(candidate, []byte(selectedImage), 0700); err != nil {
		t.Fatal(err)
	}
	endpoint := unixReloadTestEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/resources":
			_ = json.MarshalWrite(w, api.ResourceRefreshStatus{})
		case "POST /api/operations":
			var request api.OperationRequest
			if err := json.UnmarshalRead(r.Body, &request); err != nil || request.ExecutablePID != os.Getpid() {
				t.Errorf("request = %+v, %v", request, err)
			}
			peerFD := func(fd int) string { return fmt.Sprintf("/proc/%d/fd/%d", request.ExecutablePID, fd) }
			if selected, err := os.ReadFile(peerFD(request.ExecutableFD)); err != nil || string(selected) != selectedImage {
				t.Errorf("candidate = %q, %v", selected, err)
			}
			logFD, err := strconv.Atoi(r.Header.Get(api.ReloadLogFDHeader))
			if err != nil || logFD < 3 {
				t.Error("missing log descriptor")
				http.Error(w, "invalid log descriptor", 400)
				return
			}
			writer, err := os.OpenFile(peerFD(logFD), os.O_WRONLY, 0)
			if err != nil {
				t.Error(err)
				http.Error(w, "missing log pipe", 400)
				return
			}
			fmt.Fprintln(writer, "Initializing \x1b[31mdatapath\x1b[0m")
			writer.Close()
			w.WriteHeader(http.StatusAccepted)
			_ = json.MarshalWrite(w, api.Operation{ID: "mine", Kind: "reload", State: "running"})
		case "GET /api/operations/mine":
			// Do not publish completion until the CLI has actually displayed the log.
			_ = logs.SetReadDeadline(time.Now().Add(3 * time.Second))
			if line, err := bufio.NewReader(logs).ReadString('\n'); err != nil || line != "Initializing datapath\n" {
				t.Errorf("live stderr = %q, %v", line, err)
			}
			_ = json.MarshalWrite(w, api.Operation{ID: "mine", Kind: "reload", State: "completed", Progress: "old stage", Result: "Replaced"})
		default:
			http.NotFound(w, r)
		}
	})
	command := newReloadCommand(false)
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(stderr)
	command.SetArgs([]string{"--api", endpoint, "--binary", candidate})
	if err := command.ExecuteContext(t.Context()); err != nil || stdout.String() != "Replaced\n" {
		t.Fatalf("stdout = %q, %v", stdout.String(), err)
	}
}

func TestLocalReloadFallsBackToPolledProgress(t *testing.T) {
	stages, stderr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stages.Close()
	defer stderr.Close()
	var submits, polls atomic.Int32
	endpoint := unixReloadTestEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		op := api.Operation{ID: "old", Kind: "reload", State: "running", Progress: "Checking replacement executable..."}
		switch r.Method + " " + r.URL.Path {
		case "POST /api/operations":
			// This daemon ignores the optional log header.
			submits.Add(1)
			w.WriteHeader(http.StatusAccepted)
		case "GET /api/operations/old":
			if polls.Add(1) == 2 {
				_ = stages.SetReadDeadline(time.Now().Add(3 * time.Second))
				if line, err := bufio.NewReader(stages).ReadString('\n'); err != nil || line != op.Progress+"\n" {
					t.Errorf("live fallback progress = %q, %v", line, err)
				}
				op.State, op.Result = "completed", "Replaced"
			}
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.MarshalWrite(w, op)
	})
	command := newReloadCommand(false)
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(stderr)
	command.SetArgs([]string{"--api", endpoint})
	if err := command.ExecuteContext(t.Context()); err != nil || stdout.String() != "Replaced\n" || submits.Load() != 1 {
		t.Fatalf("stdout = %q, submits = %d, err = %v", stdout.String(), submits.Load(), err)
	}
}

func captureTerminal(t *testing.T, master *os.File) (*strings.Builder, func(string)) {
	t.Helper()
	fd := int(master.Fd())
	var transcript strings.Builder
	consumed := 0
	readUntil := func(want string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			if i := strings.Index(transcript.String()[consumed:], want); i >= 0 {
				consumed += i + len(want)
				return
			}
			ms := time.Until(deadline).Milliseconds()
			if ms <= 0 {
				t.Fatalf("missing %q in terminal output %q", want, transcript.String())
			}
			ready, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, int(ms))
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if ready != 0 {
				var buf [4096]byte
				n, err := master.Read(buf[:])
				if err != nil {
					t.Fatal(err)
				}
				transcript.Write(buf[:n])
			}
		}
	}
	return &transcript, readUntil
}

func TestReloadTerminalScrollback(t *testing.T) {
	for _, term := range []string{"xterm-256color", "dumb"} {
		t.Run(term, func(t *testing.T) {
			t.Setenv("TERM", term)
			master, tty := openTestPTY(t)
			transcript, readUntil := captureTerminal(t, master)

			display := newReloadProgress(tty, io.Discard, "reload")
			defer display.Stop()
			const clearLine = "\r\x1b[2K"
			if term != "dumb" {
				readUntil("⠙ Connecting to the daemon...")
				display.Hint("Opening replacement executable...")
				readUntil("Opening replacement executable...")
			}
			source, err := display.openLogPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if term != "dumb" {
				display.observe(&api.Operation{State: "queued"})
				readUntil("Queued for reload...")
			}
			handoff.WriteStage(source, "Starting replacement...")
			if term != "dumb" {
				readUntil("Starting replacement...")
			}
			display.observe(&api.Operation{State: "running", Progress: "Superseded API stage"})
			fmt.Fprintln(source, "\x1b[31mstartup log\x1b[0m")
			if term == "dumb" {
				readUntil("Starting replacement...\r\nstartup log\r\n")
			} else {
				readUntil(clearLine + "startup log\r\n")
				readUntil("Starting replacement...") // The stage is redrawn below the log.
			}
			source.Close()
			if term != "dumb" {
				readUntil("Waiting for daemon confirmation...")
			}
			display.Stop()
			fmt.Fprintln(tty, "finished")
			if term == "dumb" {
				readUntil("finished\r\n")
				if got := transcript.String(); got != "Starting replacement...\r\nstartup log\r\nfinished\r\n" {
					t.Fatalf("plain terminal output = %q", got)
				}
			} else {
				readUntil(clearLine + "finished\r\n")
				if got := transcript.String(); strings.Count(got, "startup log") != 1 || strings.Contains(got, "Superseded") || strings.Contains(got, "\x1b[31m") {
					t.Fatalf("unexpected terminal output: %q", got)
				}
			}
		})
	}
}

func TestSuspendShowsProgressUntilSubmissionFails(t *testing.T) {
	t.Setenv("TERM", "xterm")
	master, tty := openTestPTY(t)
	_, readUntil := captureTerminal(t, master)
	reject := make(chan struct{})
	endpoint := unixReloadTestEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-reject:
			http.Error(w, "rejected", http.StatusBadRequest)
		case <-r.Context().Done():
		}
	})
	command := newReloadCommand(true)
	command.SetErr(tty)
	command.SetArgs([]string{"--api", endpoint})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- command.ExecuteContext(ctx) }()
	readUntil("Submitting suspend...")
	close(reject)
	if err := <-done; err == nil {
		t.Fatal("expected submission failure")
	}
	readUntil("\r\x1b[2KError:")
}

func TestLocalReloadSurvivesStderrPipe(t *testing.T) {
	const endpointEnv = "DAE_TEST_RELOAD_STDERR_ENDPOINT"
	if endpoint := os.Getenv(endpointEnv); endpoint != "" {
		command := newReloadCommand(false)
		command.SetArgs([]string{"--api", endpoint})
		if err := command.ExecuteContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	for _, full := range []bool{true, false} {
		t.Run(map[bool]string{true: "full", false: "reader closes"}[full], func(t *testing.T) {
			stderrRead, stderrWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stderrRead.Close()
			defer stderrWrite.Close()
			stderrFD := stderrWrite.Fd()
			if full {
				size, err := unix.FcntlInt(stderrFD, unix.F_GETPIPE_SZ, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := stderrWrite.Write(make([]byte, size)); err != nil {
					t.Fatal(err)
				}
			}
			endpoint := unixReloadTestEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
				op := api.Operation{ID: "mine", Kind: "reload", State: "running"}
				switch r.Method + " " + r.URL.Path {
				case "POST /api/operations":
					var request api.OperationRequest
					fd, err := strconv.Atoi(r.Header.Get(api.ReloadLogFDHeader))
					if err != nil || fd < 3 || json.UnmarshalRead(r.Body, &request) != nil {
						t.Error("invalid local reload request")
						http.Error(w, "invalid request", 400)
						return
					}
					writer, err := os.OpenFile(fmt.Sprintf("/proc/%d/fd/%d", request.ExecutablePID, fd), os.O_WRONLY|unix.O_NONBLOCK, 0)
					if err != nil {
						t.Error(err)
						http.Error(w, "cannot open logs", 400)
						return
					}
					defer writer.Close()
					fmt.Fprintln(writer, "First log")
					if !full {
						_ = stderrRead.SetReadDeadline(time.Now().Add(3 * time.Second))
						if line, err := bufio.NewReader(stderrRead).ReadString('\n'); err != nil || line != "First log\n" {
							t.Errorf("first log = %q, %v", line, err)
						}
						_ = stderrRead.Close()
						fmt.Fprintln(writer, "Log after reader has closed")
					}
					w.WriteHeader(http.StatusAccepted)
				case "GET /api/operations/mine":
					op.State, op.Result = "completed", "Replaced"
				default:
					http.NotFound(w, r)
					return
				}
				_ = json.MarshalWrite(w, op)
			})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLocalReloadSurvivesStderrPipe$")
			command.Env = append(os.Environ(), endpointEnv+"="+endpoint)
			command.Stderr = stderrWrite
			if output, err := command.Output(); err != nil || string(output) != "Replaced\n" {
				t.Fatalf("stdout = %q, err = %v", output, err)
			}
			if flags, err := unix.FcntlInt(stderrFD, unix.F_GETFL, 0); err != nil || flags&unix.O_NONBLOCK != 0 {
				t.Fatalf("stderr flags changed: %x, %v", flags, err)
			}
		})
	}
}

type stalledReloadLogWriter struct {
	started chan struct{}
	release chan struct{}
}

func TestReloadFullTerminalDoesNotBlockCompletion(t *testing.T) {
	t.Setenv("TERM", "xterm")
	master, tty := openTestPTY(t)
	fd, err := unix.Open(tty.Name(), unix.O_WRONLY|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var fill [4096]byte
	for {
		if _, err := unix.Write(fd, fill[:]); err == unix.EAGAIN {
			break
		} else if err != nil && err != unix.EINTR {
			t.Fatal(err)
		}
	}
	display := newReloadProgress(tty, io.Discard, "reload")
	source, err := display.openLogPipe()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(source, "Startup completed")
	source.Close()
	done := make(chan struct{})
	go func() {
		display.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		master.Close() // Release any blocked writer before reporting failure.
		t.Fatal("unread terminal held up reload")
	}
}

func (w stalledReloadLogWriter) Write(data []byte) (int, error) {
	close(w.started)
	<-w.release
	return len(data), nil
}

func TestReloadLogDrainBoundsBlockedWriter(t *testing.T) {
	output := stalledReloadLogWriter{started: make(chan struct{}), release: make(chan struct{})}
	defer close(output.release)
	display := newReloadProgress(output, io.Discard, "reload")
	source, err := display.openLogPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	fmt.Fprintln(source, "Initializing...")
	source.Close()
	select {
	case <-output.started:
	case <-time.After(3 * time.Second):
		t.Fatal("log writer did not start")
	}
	done := make(chan struct{})
	go func() {
		display.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("drain waited for a blocked log writer")
	}
}
