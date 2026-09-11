// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/mitm/surge"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/control"
)

func TestPluginPreflightBeforeStartupResources(t *testing.T) {
	for _, last := range []string{`missing {}`, `bad { type: surge unknown_field: secret }`} {
		for _, reload := range []bool{false, true} {
			t.Run(last+"/reload="+strconv.FormatBool(reload), func(t *testing.T) {
				dir := t.TempDir()
				t.Setenv("DAE_LOCATION_CACHE", dir)
				// Both the first module and the CA would need resource preparation.
				conf := mitmConfigForTest(t, `mitm { enabled:true ca_cert:absent.pem ca_key:absent.key }
plugins { surge { module { 'https://invalid.example/module' } } `+last+` }`)
				calls := 0
				definition := surge.Plugin
				definition.Setup = func(context.Context, plugin.Spec, plugin.Services) (plugin.Plugin, error) {
					calls++
					t.Fatal("preflight ran setup")
					return nil, nil
				}
				definitions := map[string]plugin.Definition{"surge": definition}
				var bpf *control.BPFState
				if reload {
					bpf = &control.BPFState{}
				}
				plane, err := newControlPlane(t.Context(), bpf, conf, nil, nil, definitions)
				if plane != nil || err == nil || !strings.Contains(err.Error(), "validate plugins: plugins.") || strings.Contains(err.Error(), "secret") {
					t.Fatalf("startup preflight: plane=%v error=%v", plane, err)
				}
				if calls != 0 {
					t.Fatal("prepared a preceding plugin")
				}
				// Direct host loading must also reject before attempting the CA.
				host, err := loadMITM(t.Context(), conf, http.DefaultClient, http.DefaultClient, definitions)
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
}

func TestPluginPreflightSkipsDisabledInstances(t *testing.T) {
	conf := mitmConfigForTest(t, `plugins { absent {enabled:false} invalid {type:surge enabled:false unknown:secret} }`)
	if err := validatePlugins(conf, map[string]plugin.Definition{"surge": surge.Plugin}); err != nil {
		t.Fatal(err)
	}
}
