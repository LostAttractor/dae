/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/internal/daemon"
)

func TestSuspendUsesAcceptedConfigAfterFailedReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.dae")
	if err := os.WriteFile(path, []byte("invalid configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	current := &config.Config{Global: config.Global{
		LanInterface: []string{"lan0"}, WanInterface: []string{"wan0"},
		TproxyPort: 12345, LogLevel: "debug",
	}}
	if _, _, err := daemon.LoadReloadConfig(path, current, false); err == nil {
		t.Fatal("invalid reload succeeded")
	}
	next, _, err := daemon.LoadReloadConfig(path, current, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Global.LanInterface) != 0 || len(next.Global.WanInterface) != 0 || next.Global.LogLevel != "warning" || next.Global.TproxyPort != current.Global.TproxyPort {
		t.Fatalf("suspended configuration = %+v", next.Global)
	}
	if current.Global.LanInterface[0] != "lan0" || current.Global.WanInterface[0] != "wan0" || current.Global.LogLevel != "debug" {
		t.Fatal("preparing suspend mutated the active configuration")
	}
}

func testReloadWaitOptions(path string) reloadWaitOptions {
	return reloadWaitOptions{
		progressPath: path,
		timeout:      250 * time.Millisecond,
		pollInterval: 5 * time.Millisecond,
	}
}

func writeTestReloadState(t *testing.T, path string, code byte, content string) {
	t.Helper()
	data := []byte{code}
	if content != "" {
		data = append(data, []byte("\n"+content)...)
	}
	if err := daemon.WriteFileAtomic(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForReloadReturnsDaemonError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress")
	writeTestReloadState(t, path, consts.ReloadError, "bad config")

	_, err := waitForReload(testReloadWaitOptions(path))
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
		writeErr <- daemon.WriteFileAtomic(path, []byte{consts.ReloadDone, '\n', 'O', 'K'}, 0600)
	}()

	var progress []string
	opts := testReloadWaitOptions(path)
	opts.onProgress = func(content string) { progress = append(progress, content) }
	result, err := waitForReload(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-writeErr; err != nil {
		t.Fatal(err)
	}
	if result != "OK" || len(progress) != 1 || progress[0] != "building" {
		t.Fatalf("result/progress = %q/%v", result, progress)
	}
}

func TestWaitForReloadTimesOut(t *testing.T) {
	for _, code := range []byte{consts.ReloadSend, consts.ReloadProcessing} {
		path := filepath.Join(t.TempDir(), "progress")
		writeTestReloadState(t, path, code, "activating")
		opts := testReloadWaitOptions(path)
		opts.timeout = 30 * time.Millisecond
		_, err := waitForReload(opts)
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("code %q: waitForReload() = %v", code, err)
		}
		if code == consts.ReloadProcessing && !strings.Contains(err.Error(), "activating") {
			t.Fatal(err)
		}
	}
}

func TestWaitForReloadDoesNotHideReadErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	_, err := waitForReload(testReloadWaitOptions(path))
	if err == nil || !strings.Contains(err.Error(), "failed to read reload progress") {
		t.Fatalf("waitForReload() error = %v", err)
	}
}
