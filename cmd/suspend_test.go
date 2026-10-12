/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

func TestParsePositivePID(t *testing.T) {
	for _, raw := range []string{"", "dae", "0", "-1", "-42", "2147483648", "4294967295", "4294967296"} {
		if _, err := parsePositivePID(raw); err == nil {
			t.Errorf("parsePositivePID(%q) unexpectedly succeeded", raw)
		}
	}
	if pid, err := parsePositivePID("123"); err != nil || pid != 123 {
		t.Fatalf("parsePositivePID(123) = %d, %v", pid, err)
	}
}

func TestSuspendWaitsForDaemonCompletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress")
	writeTestReloadState(t, path, consts.ReloadSend, "")
	opts := testReloadWaitOptions(path)
	opts.operation = "suspend"
	polls := 0
	opts.processAlive = func() error {
		polls++
		switch polls {
		case 2:
			writeTestReloadState(t, path, consts.ReloadProcessing, "Publishing replacement routing...")
		case 4:
			writeTestReloadState(t, path, consts.ReloadDone, "Suspended traffic interception")
		}
		return nil
	}
	var stages []string
	opts.onProgress = func(stage string) { stages = append(stages, stage) }
	result, err := waitForReload(opts)
	if err != nil || polls < 5 || result != "Suspended traffic interception" {
		t.Fatalf("suspend completed before daemon confirmation: polls=%d result=%q err=%v", polls, result, err)
	}
	if len(stages) != 1 || stages[0] != "Publishing replacement routing..." {
		t.Fatalf("unexpected stages: %v", stages)
	}
}

func TestSuspendWaitReportsFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		code    byte
		content string
		alive   func() error
		want    string
	}{
		{name: "daemon error", code: consts.ReloadError, content: "cannot detach interface", want: "cannot detach interface"},
		{name: "empty daemon error", code: consts.ReloadError, want: "suspend failed"},
		{name: "unacknowledged", code: consts.ReloadSend, want: "suspend timed out"},
		{name: "stalled", code: consts.ReloadProcessing, content: "Publishing replacement routing...", want: "last step: Publishing replacement routing..."},
		{name: "daemon stopped", code: consts.ReloadSend, alive: func() error { return syscall.ESRCH }, want: "dae stopped during suspend"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "progress")
			writeTestReloadState(t, path, tc.code, tc.content)
			opts := testReloadWaitOptions(path)
			opts.operation = "suspend"
			opts.timeout = 20 * time.Millisecond
			opts.processAlive = tc.alive
			result, err := waitForReload(opts)
			if result != "" || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("result=%q error=%v; want %q", result, err, tc.want)
			}
		})
	}
}
