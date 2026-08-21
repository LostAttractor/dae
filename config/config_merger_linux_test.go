//go:build linux

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMergerRejectsFifoWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.dae")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := NewMerger(path).Merge()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("Merge FIFO error = %v, want regular-file error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Merge blocked while opening FIFO")
	}
}

func TestMergerRejectsOversizedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.dae")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxConfigFileSize + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewMerger(path).Merge(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Merge oversized entry error = %v, want size error", err)
	}
}
