// SPDX-License-Identifier: AGPL-3.0-only

package filewatch

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func waitForChange(t *testing.T, w *Watcher) {
	t.Helper()
	select {
	case _, ok := <-w.Changes:
		if !ok {
			t.Fatal("watch closed before notification")
		}
	case err := <-w.Errors:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("no file change notification")
	}
}

func TestWatchTracksCreationAndReplacement(t *testing.T) {
	base := t.TempDir()
	t.Chdir(base)
	filename := filepath.Join("cache", "nested", "state.json")
	w, err := New(filename, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	waitForChange(t, w)
	if _, err := os.Stat(filepath.Dir(filename)); !os.IsNotExist(err) {
		t.Fatalf("watch created directories: %v", err)
	}
	write := func(file string) {
		t.Helper()
		if err := os.WriteFile(file, []byte("updated"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		write(filename)
		waitForChange(t, w)
		write(filename)
		waitForChange(t, w)
		write(filename + ".new")
		if err := os.Rename(filename+".new", filename); err != nil {
			t.Fatal(err)
		}
		waitForChange(t, w)
		if err := os.RemoveAll("cache"); err != nil {
			t.Fatal(err)
		}
		waitForChange(t, w)
	}
}

func TestWatchCoalescesChangesAndIgnoresOtherFiles(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "state.json")
	w, err := New(filename, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	waitForChange(t, w)
	for range 5 {
		if err := os.WriteFile(filename, []byte("updated"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	waitForChange(t, w)
	if err := os.WriteFile(filename+".other", nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.Changes:
		t.Fatal("duplicate notification or unrelated file change")
	case err := <-w.Errors:
		t.Fatal(err)
	case <-time.After(250 * time.Millisecond):
	}
}

func TestWatchTracksAncestorReplacement(t *testing.T) {
	base := t.TempDir()
	ancestor := filepath.Join(base, "dae")
	filename := filepath.Join(ancestor, "cache", "state.json")
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		t.Fatal(err)
	}
	w, err := New(filename, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	waitForChange(t, w)
	for _, name := range []string{"first", "second"} {
		replacement := filepath.Join(base, "replacement", "cache")
		if err := os.MkdirAll(replacement, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(replacement, "state.json"), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
		old := ancestor + "." + name
		if err := os.Rename(ancestor, old); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Dir(replacement), ancestor); err != nil {
			t.Fatal(err)
		}
		waitForChange(t, w)
		if err := os.WriteFile(filename, []byte("updated"), 0600); err != nil {
			t.Fatal(err)
		}
		waitForChange(t, w)
		// The moved-away directory must no longer emit changes for this path.
		if err := os.WriteFile(filepath.Join(old, "cache", "state.json"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		select {
		case <-w.Changes:
			t.Fatal("still watching the old directory")
		case err := <-w.Errors:
			t.Fatal(err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func TestWatchOverflowResyncAndCloseWithoutConsumer(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "state.json")
	w, err := New(filename, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	waitForChange(t, w)
	// Simulate losing a directory event: overflow recovery must reinstall the
	// watch as well as ask the consumer to reread the file.
	if err := w.watcher.Remove(filepath.Dir(filename)); err != nil {
		t.Fatal(err)
	}
	w.watcher.Errors <- fsnotify.ErrEventOverflow
	select {
	case err := <-w.Errors:
		if !errors.Is(err, fsnotify.ErrEventOverflow) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watch error was not reported")
	}
	waitForChange(t, w)
	if err := os.WriteFile(filename, []byte("after overflow"), 0600); err != nil {
		t.Fatal(err)
	}
	waitForChange(t, w)
	// Full output channels must not prevent processing or shutdown.
	for range 3 {
		w.watcher.Errors <- fsnotify.ErrEventOverflow
	}
	closed := make(chan error, 1)
	go func() { closed <- w.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close blocked without a consumer")
	}
}
