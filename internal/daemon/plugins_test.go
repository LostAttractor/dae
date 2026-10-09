package daemon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/mitm/surge"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func loadTestMITM(ctx context.Context, conf *config.Config, client, background *http.Client, definitions map[string]plugin.Definition) (*mitm.Host, error) {
	plugins, err := configurePlugins(conf, definitions)
	if err != nil {
		return nil, err
	}
	prepared, err := loadMITM(ctx, conf, client, background, plugins, nil, nil)
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

func TestLoadMITMInstances(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	if err := os.WriteFile(filepath.Join(dir, "host.sgmodule"), []byte("[Host]\napi.example.com = 198.51.100.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	body := `mitm { enabled: false ca_cert: 'absent.pem' ca_key: 'absent.key' }
plugins {
 first { type: surge module { 'file:host.sgmodule' } }
 disabled { type: unavailable enabled: false token: 'private' }
 second { type: surge module { 'file:host.sgmodule' } }
}`
	h, err := loadTestMITM(t.Context(), mitmConfigForTest(t, body), http.DefaultClient, http.DefaultClient, map[string]plugin.Definition{"surge": surge.Plugin})
	if err != nil {
		t.Fatal(err)
	}
	if h.Authority() != nil || len(h.Status()) != 2 || len(h.Plan().Destinations) != 0 || len(h.Plan().DNS) != 2 {
		t.Fatalf("unexpected host plan: %+v", h.Plan())
	}
	if h.Status()[0].ID != "first" || h.Status()[1].ID != "second" {
		t.Fatal("instance order changed")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
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

func TestMITMInstancesDefaultStoreIsolation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	if err := mitmca.Generate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"), "store test", time.Hour); err != nil {
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
	conf := mitmConfigForTest(t, `mitm { enabled: true ca_cert: 'ca.pem' ca_key: 'ca.key' }
plugins {
 first {type:surge module {'file:first.sgmodule'}}
 second {type:surge module {'file:second.sgmodule'}}
 }`)
	host, err := loadTestMITM(t.Context(), conf, http.DefaultClient, http.DefaultClient, map[string]plugin.Definition{"surge": surge.Plugin})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	for i, id := range []string{"first", "second", "first"} {
		handler, closeTransport := host.Handler("http", id+".test", 80, nil)
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
