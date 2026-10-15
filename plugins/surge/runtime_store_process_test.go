// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeStoreProcessHelper(t *testing.T) {
	path := os.Getenv("DAE_TEST_STORE_PATH")
	if path == "" {
		t.Skip("subprocess helper")
	}
	store, err := openRuntimeStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 16 {
		key := fmt.Sprintf("%s-%d", os.Getenv("DAE_TEST_STORE_WRITER"), i)
		if !store.write(t.Context(), key, key, false) {
			t.Fatalf("could not write %s", key)
		}
	}
}

func TestRuntimeStoreMultipleProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	parent, err := openRuntimeStore(path)
	if err != nil || !parent.write(t.Context(), "cookie", "captured", false) {
		t.Fatalf("initialize store: %v", err)
	}
	var commands []*exec.Cmd
	var outputs []*bytes.Buffer
	for _, id := range []string{"a", "b"} {
		command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRuntimeStoreProcessHelper$", "-test.timeout=20s")
		command.Env = append(os.Environ(), "DAE_TEST_STORE_PATH="+path, "DAE_TEST_STORE_WRITER="+id)
		output := new(bytes.Buffer)
		command.Stdout, command.Stderr = output, output
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		commands, outputs = append(commands, command), append(outputs, output)
	}
	for i, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatalf("writer failed: %v\n%s", err, outputs[i])
		}
	}
	// This object predates both child processes, just like the daemon runtime.
	for _, id := range []string{"a", "b"} {
		for i := range 16 {
			key := fmt.Sprintf("%s-%d", id, i)
			if got, err := parent.read(t.Context(), key); err != nil || got != key {
				t.Fatalf("lost external write %s: %v, %v", key, got, err)
			}
		}
	}
	if !parent.write(t.Context(), "cookie", "", true) {
		t.Fatal("delete failed")
	}
	values, _, err := readRuntimeStoreSnapshot(path)
	if err != nil || len(values) != 32 || values["cookie"] != "" {
		t.Fatalf("stale writer overwrote child data: %v, %v", values, err)
	}
	for _, name := range []string{path, path + ".lock"} {
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("store permissions: %s %v %v", name, info, err)
		}
	}
}

func TestRuntimeStoreLockHonorsInvocationDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	store, err := openRuntimeStore(path)
	if err != nil || !store.write(t.Context(), "cookie", "original", false) {
		t.Fatal(err)
	}
	lock, err := lockRuntimeStore(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- store.write(ctx, "cookie", "changed", false) }()
	select {
	case success := <-done:
		if success || ctx.Err() == nil {
			t.Fatal("write bypassed the store lock")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("store lock ignored invocation deadline")
	}
	if value, err := store.read(t.Context(), "cookie"); err != nil || value != "original" {
		t.Fatalf("canceled write changed data: %v, %v", value, err)
	}
}

func TestRuntimeStoreLocalLockHonorsInvocationDeadline(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(fmt.Sprint(persistent), func(t *testing.T) {
			path := ""
			if persistent {
				path = filepath.Join(t.TempDir(), "store.json")
			}
			store, err := openRuntimeStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.lock(t.Context()); err != nil {
				t.Fatal(err)
			}
			defer store.unlock()
			for _, write := range []bool{false, true} {
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
				defer cancel()
				done := make(chan error, 1)
				go func() {
					if write {
						if store.write(ctx, "key", "value", false) {
							done <- errors.New("write bypassed the local lock")
						} else {
							done <- ctx.Err()
						}
						return
					}
					_, err := store.read(ctx, "key")
					done <- err
				}()
				select {
				case err := <-done:
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("write=%t: %v", write, err)
					}
				case <-time.After(time.Second):
					t.Fatalf("write=%t ignored the deadline while waiting for local store access", write)
				}
			}
		})
	}
}
