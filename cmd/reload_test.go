/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

func testReloadWaitOptions(path string) reloadWaitOptions {
	return reloadWaitOptions{
		progressPath: path,
		timeout:      250 * time.Millisecond,
		legacyGrace:  100 * time.Millisecond,
		pollInterval: 5 * time.Millisecond,
	}
}

func writeTestReloadState(t *testing.T, path string, code byte, content string) {
	t.Helper()
	data := []byte{code}
	if content != "" {
		data = append(data, []byte("\n"+content)...)
	}
	if err := writeFileAtomic(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForReloadReturnsDaemonError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress")
	writeTestReloadState(t, path, consts.ReloadError, "bad config")

	_, _, err := waitForReload(testReloadWaitOptions(path))
	if err == nil || !strings.Contains(err.Error(), "bad config") {
		t.Fatalf("waitForReload() error = %v", err)
	}
}

func TestWaitForReloadReportsProgressAndCompletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress")
	writeTestReloadState(t, path, consts.ReloadProcessing, "building")
	writeErr := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		writeErr <- writeFileAtomic(path, []byte{consts.ReloadDone, '\n', 'O', 'K'}, 0600)
	}()

	var progress []string
	opts := testReloadWaitOptions(path)
	opts.onProgress = func(content string) { progress = append(progress, content) }
	result, legacy, err := waitForReload(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-writeErr; err != nil {
		t.Fatal(err)
	}
	if result != "OK" || legacy || len(progress) != 1 || progress[0] != "building" {
		t.Fatalf("result/legacy/progress = %q/%v/%v", result, legacy, progress)
	}
}

func TestWaitForReloadTimesOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress")
	writeTestReloadState(t, path, consts.ReloadProcessing, "activating")
	opts := testReloadWaitOptions(path)
	opts.timeout = 30 * time.Millisecond

	_, _, err := waitForReload(opts)
	if err == nil || !strings.Contains(err.Error(), "timed out") || !strings.Contains(err.Error(), "activating") {
		t.Fatalf("waitForReload() error = %v", err)
	}
}

func TestWaitForReloadDoesNotHideReadErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	_, _, err := waitForReload(testReloadWaitOptions(path))
	if err == nil || !strings.Contains(err.Error(), "failed to read reload progress") {
		t.Fatalf("waitForReload() error = %v", err)
	}
}

func TestWaitForReloadLegacyFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress")
	writeTestReloadState(t, path, consts.ReloadSend, "")
	opts := testReloadWaitOptions(path)
	opts.legacyGrace = 20 * time.Millisecond

	result, legacy, err := waitForReload(opts)
	if err != nil || result != "OK" || !legacy {
		t.Fatalf("waitForReload() = %q, legacy=%v, err=%v", result, legacy, err)
	}
}
