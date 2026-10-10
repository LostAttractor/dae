// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestSurgeRuntimeConfig(t *testing.T) {
	for _, test := range []struct {
		settings, path string
		invalid        bool
	}{
		{path: "node"},
		{settings: `node_path: '/opt/node/bin/node'`, path: "/opt/node/bin/node", invalid: compiledJSRuntime != "nodejs"},
		{settings: `js_runtime: quickjs`, invalid: true},
		{settings: `js_runtime: nodejs`, invalid: true},
		{settings: `node_path: ''`, invalid: true},
	} {
		sections, err := config_parser.Parse("surge { " + test.settings + " module { 'file:module' } }")
		if err != nil {
			t.Fatal(err)
		}
		conf, err := ParseConfig(sections[0])
		if test.invalid {
			if err == nil {
				t.Fatalf("accepted %s", test.settings)
			}
		} else if err != nil || conf.NodePath != test.path {
			t.Fatalf("config=%+v err=%v", conf, err)
		}
	}
}

func TestRuntimeBuildSelection(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-node")
	r, err := NewRuntime(t.Context(), RuntimeOptions{NodePath: missing})
	if compiledJSRuntime == "nodejs" {
		if err == nil || !strings.Contains(err.Error(), "executable") {
			t.Fatalf("Node build accepted missing executable: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("QuickJS build requires Node: %v", err)
	}
	defer r.Close()
}

func TestPrepareCanceledRuntime(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	engine, err := prepare(ctx, Config{
		MemoryLimit: 64 << 20, MaxBodySize: 1 << 20,
		MaxConcurrentScripts: 1, ScriptTimeout: DefaultScriptTimeout,
	}, plugin.Services{Prepared: []*Module{}, BodyMemory: testBodyMemory}, "test")
	if engine != nil {
		_ = engine.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("prepared resources bypassed startup cancellation: %v", err)
	}
}
