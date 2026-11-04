// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestInstanceLockExcludesOwnersAndSurvivesFileReuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dae.lock")
	first, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if other, err := acquireInstanceLock(path); err == nil {
		other.Close()
		t.Fatal("second owner acquired an active daemon lock")
	}
	before, err := first.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	after, err := second.Stat()
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("lock inode was replaced: %v", err)
	}
}

func TestInstanceLockReleasedOnProcessDeath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dae.lock")
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestInstanceLockChild$")
	child.Env = append(os.Environ(), "DAE_INSTANCE_LOCK_CHILD="+path)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("child did not acquire lock: %q, %v", line, err)
	}
	if other, err := acquireInstanceLock(path); err == nil {
		other.Close()
		t.Fatal("a second daemon could race a running daemon")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	replacement, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatalf("dead daemon retained its instance lock: %v", err)
	}
	replacement.Close()
}

func TestInstanceLockChild(t *testing.T) {
	path := os.Getenv("DAE_INSTANCE_LOCK_CHILD")
	if path == "" {
		t.Skip("subprocess helper")
	}
	instance, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	fmt.Println("locked")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func TestInstanceLockRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dae.lock")
	if err := os.Symlink(filepath.Join(dir, "target"), path); err != nil {
		t.Fatal(err)
	}
	if file, err := acquireInstanceLock(path); err == nil {
		file.Close()
		t.Fatal("followed an instance lock symlink")
	}
}
