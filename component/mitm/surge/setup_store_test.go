// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	log "github.com/sirupsen/logrus"
)

func TestConfiguredStoreDefaultsAndMemoryOptOut(t *testing.T) {
	base := t.TempDir()
	for name, contents := range map[string]string{
		"module.sgmodule": "[Script]\ncounter=type=cron,cronexp=0 0 * * *,script-path=counter.js\nmanual=type=generic,script-path=counter.js",
		"counter.js": `
const next = Number($persistentStore.read("count") || "0") + 1;
if (!$persistentStore.write(String(next), "count")) throw Error("write failed");
$done();`,
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	logger := log.New()
	logger.SetOutput(io.Discard)
	run := func(instance, setting, script, want string) {
		t.Helper()
		sections, err := config_parser.Parse("surge { module { 'file:module.sgmodule' } " + setting + " }")
		if err != nil {
			t.Fatal(err)
		}
		factory, err := Configure(plugin.Spec{ID: instance, Type: "surge", Config: sections[0]})
		if err != nil {
			t.Fatal(err)
		}
		p, err := factory(t.Context(), plugin.Services{BaseDir: base, PrepareClient: http.DefaultClient, BodyMemory: testBodyMemory, Logger: log.NewEntry(logger)})
		if err != nil {
			t.Fatal(err)
		}
		e := p.(*Engine)
		synctest.Test(t, func(t *testing.T) {
			host := startCronTestHost(t, e, http.DefaultClient)
			if _, err := host.TriggerScript("test", api.ScriptRunRequest{Script: script}); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			for _, status := range e.Status().Modules[0].Tasks {
				if status.Name == script && (status.LastResult != "success" || status.Runs != 1) {
					t.Fatalf("counter task failed: %+v", status)
				}
			}
		})
		if got, err := e.options.Runtime.data.read(t.Context(), "count"); err != nil || got != want {
			t.Fatalf("instance=%s setting=%q count=%v, want %s, error=%v", instance, setting, got, want, err)
		}
	}
	run("personal", "", "counter", "1")
	run("personal", "", "manual", "2")
	run("work", "", "manual", "1")
	path := filepath.Join(base, "plugins", "personal", "surge-store.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	run("personal", "store: false", "manual", "1")
	run("personal", "store: false", "counter", "1")
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("memory mode modified persistent data: before=%s after=%s err=%v", before, after, err)
	}
	run("personal", "store: true", "manual", "3")
	run("ephemeral", "store: false", "manual", "1")
	if _, err := os.Stat(filepath.Join(base, "plugins", "ephemeral")); !os.IsNotExist(err) {
		t.Fatalf("memory mode created store files: %v", err)
	}
}
