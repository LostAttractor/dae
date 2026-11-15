package daemon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/plugins/surge"
)

func loadTestMITM(ctx context.Context, conf *config.Config, client, background *http.Client, definitions map[string]plugin.Definition) (*mitm.Host, error) {
	plugins, err := configurePlugins(conf, definitions)
	if err != nil {
		return nil, err
	}
	certificates, err := prepareCertificates(conf, nil)
	if err != nil {
		return nil, err
	}
	prepared, err := loadMITM(ctx, conf, certificates.Authority(), client, background, plugins, nil, nil, nil)
	return prepared.Host, err
}

func mitmConfigForTest(t *testing.T, body string) *config.Config {
	t.Helper()
	s, err := config_parser.Parse("global {}\n" + body + "\nrouting { fallback: direct }")
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDisabledPluginStatusAcceptsWithoutHost(t *testing.T) {
	t.Setenv("DAE_LOCATION_CACHE", t.TempDir())
	definitions := map[string]plugin.Definition{"fixture": {Configure: func(plugin.Spec) (plugin.Factory, error) {
		t.Fatal("disabled plugin was configured")
		return nil, nil
	}}}
	conf := mitmConfigForTest(t, "plugins { fixture: false unavailable: false }")
	conf.Global.ResourceCache = false
	app := &application{conf: conf, plane: &control.ControlPlane{}, datapath: control.NewRuntime(), definitions: definitions}
	defer app.datapath.Close()
	for _, plugins := range []config.Plugins{conf.Plugins, {{Name: "changed", Type: "uncompiled"}}, nil} {
		next := *conf
		next.Plugins = plugins
		configured, err := configurePlugins(&next, definitions)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := loadMITM(t.Context(), &next, nil, http.DefaultClient, http.DefaultClient, configured, nil, nil, nil)
		if err != nil || prepared.Host != nil {
			t.Fatalf("disabled instances created a host: %+v, %v", prepared, err)
		}
		observability, err := prepareObservabilityServers(0, 0)
		if err != nil {
			t.Fatal(err)
		}
		result, err := app.replaceServices(&next, nil, netip.AddrPort{}, nil, &prepared, func() {
			t.Fatal("disabled-only change replaced the API handler")
		}, observability)
		observability.Close()
		if err != nil || result == "" || app.plane.MITMHost() != nil {
			t.Fatalf("disabled-only accept failed: %s, %v", result, err)
		}
		status := app.plane.MITMStatus()
		if !reflect.DeepEqual(status.CompiledPlugins, []string{"fixture"}) || len(status.Plugins) != len(plugins) {
			t.Fatalf("accepted configuration not published: %+v", status)
		}
		for i, spec := range plugins {
			p := status.Plugins[i]
			if p.ID != spec.Name || p.Type != spec.Type || p.Enabled || p.State != "disabled" || len(p.Details) != 0 {
				t.Fatalf("wrong disabled projection: %+v", p)
			}
		}
		bad := next
		bad.Plugins = config.Plugins{{Name: "unavailable", Type: "unavailable", Enabled: true}}
		if _, err := app.apply(t.Context(), &bad, false, false, false); err == nil {
			t.Fatal("enabled uncompiled type was accepted")
		}
		if after := app.plane.MITMStatus(); !reflect.DeepEqual(after, status) {
			t.Fatalf("failed reload published configuration: %+v -> %+v", status, after)
		}
	}
}

func TestLoadMITMInstances(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	if err := os.WriteFile(filepath.Join(dir, "host.sgmodule"), []byte("[Host]\napi.example.com = 198.51.100.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	body := `mitm { enabled: false }
plugins {
 first { type: surge module { 'file:host.sgmodule' } }
 disabled { type: unavailable enabled: false token: 'private' }
 second { type: surge module { 'file:host.sgmodule' } }
}`
	h, err := loadTestMITM(t.Context(), mitmConfigForTest(t, body), http.DefaultClient, http.DefaultClient, map[string]plugin.Definition{"surge": surge.Plugin})
	if err != nil {
		t.Fatal(err)
	}
	if h.Authority() != nil || len(h.Status().Plugins) != 2 || len(h.Plan().Destinations) != 0 || len(h.Plan().DNS) != 2 {
		t.Fatalf("unexpected host plan: %+v", h.Plan())
	}
	if h.Status().Plugins[0].ID != "first" || h.Status().Plugins[1].ID != "second" {
		t.Fatal("instance order changed")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPluginDiagnosticIDIsReservedWhenDisabled(t *testing.T) {
	conf := mitmConfigForTest(t, "plugins { dae-mitm-test: false }")
	if _, err := configurePlugins(conf, nil); err == nil {
		t.Fatal("disabled user configuration can shadow the system diagnostic")
	}
}

func TestLoadMITMRejectsUnknownSettings(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	if err := os.WriteFile(filepath.Join(dir, "host.sgmodule"), []byte("[Host]\napi.example.com = 198.51.100.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`plugins { unknown { api_key: 'secret' } }`,
		`plugins { surge { invalid: 'secret' module { 'file:host.sgmodule' } } }`,
	} {
		h, err := loadTestMITM(t.Context(), mitmConfigForTest(t, body), http.DefaultClient, http.DefaultClient, map[string]plugin.Definition{"surge": surge.Plugin})
		if err == nil {
			h.Close()
			t.Fatal("accepted invalid instance")
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("diagnostic exposed credentials: %v", err)
		}
	}
}

type storeTestDevices struct{}

func (storeTestDevices) Identify(_ context.Context, _ netip.Addr, mac [6]byte) [6]byte {
	return mac
}

func (storeTestDevices) MITMEnabled(context.Context) ([][6]byte, error) {
	return nil, nil
}

func TestMITMInstancesDefaultStoreIsolation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	if err := localca.Generate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"), "store test", time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"first", "second"} {
		content := "[MITM]\nhostname=" + id + ".test\n[Script]\ncounter=type=http-request,pattern=.,script-path=count.js\n"
		if err := os.WriteFile(filepath.Join(dir, id+".sgmodule"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "count.js"), []byte(`const n=Number($persistentStore.read("counter")||0)+1;$persistentStore.write(String(n),"counter");$done({response:{status:200,body:String(n)}});`), 0600); err != nil {
		t.Fatal(err)
	}
	conf := mitmConfigForTest(t, `certificate { ca_cert: 'ca.pem' ca_key: 'ca.key' }
mitm { enabled: true }
plugins {
 first {type:surge module {'file:first.sgmodule'}}
 second {type:surge module {'file:second.sgmodule'}}
 }`)
	definition := surge.Plugin
	definition.Configure = func(spec plugin.Spec) (plugin.Factory, error) {
		factory, err := surge.Plugin.Configure(spec)
		if err != nil {
			return nil, err
		}
		return func(ctx context.Context, services plugin.Services) (plugin.Plugin, error) {
			services.Devices = storeTestDevices{}
			return factory(ctx, services)
		}, nil
	}
	host, err := loadTestMITM(t.Context(), conf, http.DefaultClient, http.DefaultClient, map[string]plugin.Definition{"surge": definition})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	for i, id := range []string{"first", "second", "first"} {
		handler, closeTransport := host.HandlerForFlow("http", plugin.Flow{Host: id + ".test", Port: 80, SourceOrigin: plugin.SourceLAN, SourceMAC: [6]byte{2, 0, 0, 0, 0, 1}}, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "http://"+id+".test/", nil))
		closeTransport()
		if w.Code != 200 || w.Body.String() != fmt.Sprint(i/2+1) {
			t.Fatalf("store crossed instance boundary: instance=%s code=%d body=%s", id, w.Code, w.Body.String())
		}
	}
	for _, id := range []string{"first", "second"} {
		if _, err := os.Stat(filepath.Join(dir, "plugins", id, "surge-store.json")); err != nil {
			t.Fatalf("default store was not persisted for %s: %v", id, err)
		}
	}
}

func TestMITMGlobalResourceCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "[Host]\napi.example.com = 198.51.100.1\n")
	}))
	defer server.Close()
	conf := mitmConfigForTest(t, fmt.Sprintf("plugins { surge { module { '%s' } } }", server.URL))
	if !conf.Global.ResourceCache {
		t.Fatal("resource cache must default to enabled")
	}
	load := func(wantSuccess bool) {
		t.Helper()
		host, err := loadTestMITM(t.Context(), conf, server.Client(), http.DefaultClient, map[string]plugin.Definition{"surge": surge.Plugin})
		if host != nil {
			host.Close()
		}
		if (err == nil) != wantSuccess {
			t.Fatalf("resource_cache=%t: %v", conf.Global.ResourceCache, err)
		}
	}
	conf.Global.ResourceCache = false
	load(true)
	if _, err := os.Stat(filepath.Join(dir, "resources")); !os.IsNotExist(err) {
		t.Fatalf("disabled resource cache created directory: %v", err)
	}
	conf.Global.ResourceCache = true
	load(true)
	files, err := filepath.Glob(filepath.Join(dir, "resources", "surge", "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("resource cache files: %v %v", files, err)
	}
	before, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	load(true)
	conf.Global.ResourceCache = false
	load(false)
	after, err := os.ReadFile(files[0])
	if err != nil || string(before) != string(after) {
		t.Fatalf("disabled resource cache modified existing snapshot: %v", err)
	}
}
