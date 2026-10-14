/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"os"
	"path/filepath"
	"testing"

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
