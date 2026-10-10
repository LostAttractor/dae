// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/resource"
)

func TestScriptRefreshIntervalsAndReload(t *testing.T) {
	var scriptReads, moduleReads, revision atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/module" {
			moduleReads.Add(1)
			io.WriteString(w, "[Script]\na=type=generic,script-path=./script,script-update-interval=60\nb=type=generic,script-path=script,script-update-interval=3600\n")
		} else {
			scriptReads.Add(1)
			fmt.Fprintf(w, "$done({body:'%d'});", revision.Load())
		}
	}))
	defer server.Close()
	var store resource.RefreshStore
	load := func(automatic bool) *Module {
		t.Helper()
		ctx, session := store.Begin(t.Context(), 24*time.Hour, automatic)
		module, err := Load(ctx, server.URL+"/module", server.Client(), LoadOptions{})
		if err != nil {
			t.Fatal(err)
		}
		session.Commit()
		return module
	}
	first := load(false)
	if next := time.Until(store.Next()); next <= 0 || next > time.Minute {
		t.Fatalf("script next check: %v", next)
	}
	revision.Store(1)
	if module := load(true); module.contentKey != first.contentKey || scriptReads.Load() != 1 || moduleReads.Load() != 1 {
		t.Fatal("unexpired script redownloaded or duplicated")
	}
	if module := load(false); module.TaskScripts[0].Source != "$done({body:'1'});" || module.TaskScripts[1].Source != module.TaskScripts[0].Source || module.contentKey == first.contentKey {
		t.Fatal("explicit reload did not refresh dependencies")
	}
	server.Close()
	if module := load(false); !hasModuleCacheFallback(module) || module.TaskScripts[0].Source != "$done({body:'1'});" {
		t.Fatal("offline refresh lost accepted sources without a disk cache")
	}
}

func TestDebugScriptRereadsBeforeEachInvocation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.js")
	write := func(value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("$done({body:'old'});")
	modulePath := filepath.Join(dir, "module")
	if err := os.WriteFile(modulePath, []byte("[Script]\na=type=generic,script-path=script.js,debug=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	module, err := Load(t.Context(), "file://"+modulePath, nil, LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	r := testRuntime(t, RuntimeOptions{})
	e, err := NewEngine(EngineOptions{Modules: []*Module{module}, Runtime: r.Runtime, BodyMemory: testBodyMemory,
		MaxBodySize: 1 << 20, MaxConcurrentScripts: 1, ScriptTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	script := &module.TaskScripts[0]
	for _, body := range []string{"new", "latest"} {
		write("$persistentStore.write('" + body + "', 'debug'); $done();")
		result, err := e.runInvocation(t.Context(), module, script, Invocation{})
		if err != nil {
			t.Fatal(err)
		}
		result.Close()
		if got, err := r.data.read(t.Context(), "debug"); err != nil || got != body {
			t.Errorf("debug source: %q, %v", got, err)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if result, err := e.runInvocation(t.Context(), module, script, Invocation{}); err == nil {
		result.Close()
		t.Fatal("missing debug file used a stale script")
	}
}
