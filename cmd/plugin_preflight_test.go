// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

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
			if err := Run(conf, nil, definitions, nil); err == nil || !strings.Contains(err.Error(), "plugins.") || strings.Contains(err.Error(), "secret") {
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
	if _, err := configurePlugins(conf, map[string]plugin.Definition{"surge": surge.Plugin}); err != nil {
		t.Fatal(err)
	}
}
