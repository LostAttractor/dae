// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestStartupBlockedIOFixture(t *testing.T) {
	if os.Getenv("DAE_TEST_BLOCKED_STARTUP") != "1" {
		t.Skip("subprocess fixture")
	}
	startup, err := OpenStartup()
	if err != nil {
		t.Fatal(err)
	}
	defer startup.Close()
	blocked := os.NewFile(3, "blocked-startup")
	defer blocked.Close()
	ready := os.NewFile(4, "startup-ready")
	if _, err := ready.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	ready.Close()
	// Model configuration I/O that does not accept the signal context.
	if _, err := blocked.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	t.Fatal("startup I/O unexpectedly completed")
}

func TestStartupStopBeforeRunKernel(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires root in isolated PID/network/mount namespaces with private /run")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	ready, readyWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Close()
	defer readyWriter.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestStartupBlockedIOFixture$", "-test.timeout=30s")
	command.Env = append(os.Environ(), "DAE_TEST_BLOCKED_STARTUP=1")
	command.ExtraFiles = []*os.File{reader, readyWriter}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	reader.Close()
	readyWriter.Close()
	if err := ready.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ready, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	select {
	case err := <-finished:
		failure, ok := errors.AsType[*exec.ExitError](err)
		if !ok || failure.ExitCode() != 1 || !bytes.Contains(output.Bytes(), []byte("Shutdown timed out")) {
			t.Fatalf("startup stop: %v\n%s", err, &output)
		}
	case <-time.After(shutdownTimeout + 5*time.Second):
		_ = command.Process.Kill()
		<-finished
		t.Fatalf("stop signal was consumed without a bounded exit\n%s", &output)
	}
}
