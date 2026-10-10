// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/mitm/surge"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestPluginPreflightBeforeStartupResources(t *testing.T) {
	for _, last := range []string{`missing {}`, `bad { type: surge unknown_field: secret }`} {
		t.Run(last, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("DAE_LOCATION_CACHE", dir)
			// Both the first module and the CA would need resource preparation.
			conf := mitmConfigForTest(t, `mitm { enabled:true ca_cert:absent.pem ca_key:absent.key }
plugins { surge { module { 'https://invalid.example/module' } } `+last+` }`)
			definition := surge.Plugin
			definition.Configure = func(spec plugin.Spec) (plugin.Factory, error) {
				_, err := surge.Configure(spec)
				return func(context.Context, plugin.Services) (plugin.Plugin, error) {
					t.Fatal("preflight prepared resources")
					return nil, nil
				}, err
			}
			definitions := map[string]plugin.Definition{"surge": definition}
			if err := Run(conf, nil, definitions, nil, Options{}); err == nil || !strings.Contains(err.Error(), "plugins.") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("startup preflight: error=%v", err)
			}
			// Direct host loading must also reject before attempting the CA.
			host, err := loadTestMITM(t.Context(), conf, http.DefaultClient, http.DefaultClient, definitions)
			if host != nil || err == nil || !strings.HasPrefix(err.Error(), "plugins.") {
				t.Fatalf("host preflight: host=%v error=%v", host, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("preflight wrote resource files: %v %v", entries, err)
			}
		})
	}
}

func TestPluginPreflightSkipsDisabledInstances(t *testing.T) {
	conf := mitmConfigForTest(t, `plugins { absent {enabled:false} invalid {type:surge enabled:false unknown:secret} }`)
	definition := surge.Plugin
	definition.Preflight = func(context.Context, plugin.Spec) error {
		t.Fatal("disabled instance checked runtime dependencies")
		return nil
	}
	configured, err := configurePlugins(conf, map[string]plugin.Definition{"surge": definition})
	if err != nil {
		t.Fatal(err)
	}
	if err := configured.Preflight(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestPluginRuntimePreflightBeforeResources(t *testing.T) {
	for _, reload := range []bool{false, true} {
		name := "startup"
		if reload {
			name = "reload"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("DAE_LOCATION_CACHE", dir)
			conf := mitmConfigForTest(t, `mitm { enabled:true ca_cert:absent.pem ca_key:absent.key }
plugins { fixture {} }`)
			unavailable := errors.New("runtime unavailable")
			definitions := map[string]plugin.Definition{"fixture": {
				Configure: func(plugin.Spec) (plugin.Factory, error) {
					return func(context.Context, plugin.Services) (plugin.Plugin, error) {
						t.Fatal("runtime preflight prepared a plugin")
						return nil, nil
					}, nil
				},
				Preflight: func(context.Context, plugin.Spec) error { return unavailable },
				Resources: func(context.Context, plugin.Spec, plugin.Services) (plugin.Resources, error) {
					t.Fatal("runtime preflight loaded resources")
					return plugin.Resources{}, nil
				},
			}}
			var err error
			if reload {
				app := application{conf: conf, definitions: definitions}
				_, err = app.apply(t.Context(), conf, false, false, false)
			} else {
				err = Run(conf, nil, definitions, &netutils.InternalResolver{}, Options{})
			}
			if !errors.Is(err, unavailable) || !strings.Contains(err.Error(), "plugins.fixture preflight") {
				t.Fatalf("runtime dependency was not checked first: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("preflight wrote resource files: %v %v", entries, err)
			}
		})
	}
}
