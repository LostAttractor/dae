//go:build surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
)

func prewarmTestConfig(nodePath string) Config {
	return Config{
		NodePath: nodePath, MemoryLimit: 64 << 20, MaxBodySize: 1 << 20,
		MaxConcurrentScripts: 2, ScriptTimeout: DefaultScriptTimeout,
	}
}

func TestPreparePrewarmsNodeWithoutScriptSideEffects(t *testing.T) {
	modules := []*Module{{TaskScripts: []Script{
		{Name: "manual", Type: "generic", Source: `$persistentStore.write("executed", "side-effect"); $done()`},
	}}}
	e, err := prepare(t.Context(), prewarmTestConfig("node"), plugin.Services{Prepared: modules, BodyMemory: testBodyMemory}, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if n := e.Status().Runtimes[0].NodeJS; n.Started != 1 || n.Idle != 1 || n.Active != 0 {
		t.Fatalf("preparation did not prewarm: %+v", n)
	}
	r := e.options.Runtime
	if value, err := r.data.read(t.Context(), "side-effect"); err != nil || value != nil {
		t.Fatalf("warmup executed a user script: value=%v err=%v", value, err)
	}
	result, err := r.Run(t.Context(), `$done()`, Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	result.Close()
	if n := e.Status().Runtimes[0].NodeJS; n.Started != 1 || n.Reused != 1 {
		t.Fatalf("first call did not reuse the prewarmed worker: %+v", n)
	}
}

func TestPrepareRejectsNodeWarmFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	modules := []*Module{{TaskScripts: []Script{{Name: "manual", Type: "generic"}}}}
	e, err := prepare(t.Context(), prewarmTestConfig(path), plugin.Services{Prepared: modules, BodyMemory: testBodyMemory}, "test")
	if err == nil {
		_ = e.Close()
		t.Fatal("preparation accepted a failed Node runtime")
	}
}
