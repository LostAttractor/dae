package cmd

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

	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/mitm/surge"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

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
	h, err := loadMITM(context.Background(), mitmConfigForTest(t, body), http.DefaultClient, http.DefaultClient, map[string]plugin.Definition{"surge": surge.Plugin})
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
		h, err := loadMITM(context.Background(), mitmConfigForTest(t, body), http.DefaultClient, http.DefaultClient, map[string]plugin.Definition{"surge": surge.Plugin})
		if err == nil {
			h.Close()
			t.Fatal("accepted invalid instance")
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("diagnostic exposed credentials: %v", err)
		}
	}
}

func TestMITMInstancesCanExplicitlyShareStore(t *testing.T) {
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
 first {type:surge store:'shared.json' module {'file:first.sgmodule'}}
 second {type:surge store:'shared.json' module {'file:second.sgmodule'}}
 }`)
	host, err := loadMITM(context.Background(), conf, http.DefaultClient, http.DefaultClient, map[string]plugin.Definition{"surge": surge.Plugin})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	for i, id := range []string{"first", "second", "first"} {
		handler, closeTransport := host.Handler("http", id+".test", 80, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "http://"+id+".test/", nil))
		closeTransport()
		if w.Code != 200 || w.Body.String() != fmt.Sprint(i+1) {
			t.Fatalf("store not shared: code=%d body=%s", w.Code, w.Body.String())
		}
	}
}
