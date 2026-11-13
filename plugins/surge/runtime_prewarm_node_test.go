//go:build surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
	"github.com/daeuniverse/dae/pkg/config_parser"
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
	if value, err := r.data.read(t.Context(), testLocalScope, "side-effect"); err != nil || value != nil {
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

func TestStaticResourcesDoNotStartNode(t *testing.T) {
	base := t.TempDir()
	marker := filepath.Join(base, "node-started")
	node := filepath.Join(base, "node")
	for name, contents := range map[string]string{
		"node":            fmt.Sprintf("#!/bin/sh\n: > %q\nexit 1\n", marker),
		"module.sgmodule": "[MITM]\nhostname=example.test\n[Script]\nrequest=type=http-request,pattern=.,script-path=request.js\n",
		"request.js":      "$done({});",
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(contents), 0700); err != nil {
			t.Fatal(err)
		}
	}
	sections, err := config_parser.Parse(fmt.Sprintf("surge { node_path: '%s' module { 'file:module.sgmodule' } }", node))
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := pluginhost.Configure(map[string]plugin.Definition{"surge": Plugin}, []plugin.Spec{{ID: "test", Type: "surge", Config: sections[0]}})
	if err != nil {
		t.Fatal(err)
	}
	services := plugin.Services{BaseDir: base, PrepareClient: http.DefaultClient, BodyMemory: testBodyMemory}
	prepared, err := configuration.LoadResources(t.Context(), services)
	if err != nil || prepared == nil {
		t.Fatalf("static resources required a working Node runtime: %v", err)
	}
	if len(prepared.Plan().Scopes) != 1 {
		t.Fatal("static resources omitted the HTTP script scope")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("resource loading started Node: %v", err)
	}
	if instances, err := prepared.BuildInstances(t.Context(), services, nil); err == nil || len(instances) != 0 {
		t.Fatal("instance construction accepted the failing Node runtime")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("Factory did not attempt to warm Node: %v", err)
	}
}
