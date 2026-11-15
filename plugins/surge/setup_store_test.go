// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
	"github.com/daeuniverse/dae/pkg/config_parser"
	log "github.com/sirupsen/logrus"
)

func TestIsolationReloadPreservesScopes(t *testing.T) {
	base := t.TempDir()
	for name, contents := range map[string]string{
		"module.sgmodule": "[MITM]\nhostname=scope.test\n[Script]\ncounter=type=http-request,pattern=.,script-path=counter.js",
		"counter.js": `const n=Number($persistentStore.read("count")||0)+1;
if (!$persistentStore.write(String(n),"count")) throw Error("write failed");
$done({response:{status:200,body:String(n)}});`,
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	services := plugin.Services{BaseDir: base, PrepareClient: http.DefaultClient, BodyMemory: testBodyMemory, Devices: newTestDevices()}
	var previous *pluginhost.Instance
	t.Cleanup(func() {
		if previous != nil {
			previous.Release()
		}
	})
	var contentKey string
	for i, test := range []struct {
		instance, module, local, device string
		reused                          bool
	}{
		{"", "", "1", "1", false},
		{"isolate_lan: false", "", "3", "1", false},
		{"isolate_lan: false", "", "5", "1", true},
		{"isolate_lan: true", "", "6", "2", false},
		{"isolate_lan: true", "isolate_lan: false", "8", "2", false},
		{"isolate_lan: true", "isolate_lan: true script {name: counter isolate_lan: false}", "10", "2", false},
		{"isolate_lan: true", "isolate_lan: false script {name: counter isolate_lan: true}", "11", "3", false},
		{"isolate_lan: true", "script {isolate_lan: true name: counter} isolate_lan: false", "12", "4", true},
	} {
		sections, err := config_parser.Parse("surge { module { test {link: 'file:module.sgmodule' " + test.module + "} } " + test.instance + " }")
		if err != nil {
			t.Fatal(err)
		}
		configuration, err := pluginhost.Configure(map[string]plugin.Definition{"surge": Plugin}, []plugin.Spec{{ID: "personal", Type: "surge", Config: sections[0]}})
		if err != nil {
			t.Fatal(err)
		}
		var old []*pluginhost.Instance
		if previous != nil {
			old = []*pluginhost.Instance{previous}
		}
		prepared, err := configuration.Prepare(t.Context(), services, old)
		if err != nil {
			t.Fatal(err)
		}
		current := prepared[0].Instance
		reused := current == previous
		if previous != nil {
			previous.Release()
		}
		previous = current
		if reused != test.reused {
			t.Fatalf("isolation change reused the wrong instance: step=%d reused=%t", i, reused)
		}
		e := current.Plugin.(*Engine)
		if i == 0 {
			contentKey = e.options.Modules[0].contentKey
		} else if contentKey != e.options.Modules[0].contentKey {
			t.Fatal("local execution policy changed module resource identity")
		}
		for _, origin := range []plugin.SourceOrigin{plugin.SourceLocal, plugin.SourceLAN} {
			request := httptest.NewRequest("GET", "https://scope.test/", nil)
			flow := plugin.Flow{Host: "scope.test", Port: 443, SourceOrigin: origin, SourceMAC: testDeviceMAC}
			response, err := e.Wrap(flow, func(*plugin.Exchange) (*plugin.Response, error) {
				t.Fatal("counter did not return a response")
				return nil, nil
			})(&plugin.Exchange{Request: plugin.NewRequest(request, e.options.BodyMemory), Client: http.DefaultClient})
			if err != nil {
				t.Fatal(err)
			}
			response.Close()
		}
		for scope, want := range map[ScriptScope]string{
			testLocalScope:  test.local,
			testDeviceScope: test.device,
		} {
			if got, err := e.options.Runtime.data.read(t.Context(), scope, "count"); err != nil || got != want {
				t.Fatalf("step=%d scope=%+v count=%v want=%s error=%v", i, scope, got, want, err)
			}
		}
	}
}

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
		runtimeFakeClockTest(t, func(t *testing.T) {
			host := startCronTestHost(t, e, http.DefaultClient)
			if _, err := host.TriggerScript(t.Context(), "test", api.ScriptRunRequest{Script: script}); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			for _, status := range e.Status().Modules[0].Tasks {
				if status.Name == script && (status.LastResult != "success" || status.Runs != 1) {
					t.Fatalf("counter task failed: %+v", status)
				}
			}
		})
		if got, err := e.options.Runtime.data.read(t.Context(), testLocalScope, "count"); err != nil || got != want {
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
