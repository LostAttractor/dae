// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/internal/handoff"
)

func TestPreparedInputsRebuildWithoutLiveSources(t *testing.T) {
	// Linux paths are byte strings, including across the sealed input transport.
	dir := filepath.Join(t.TempDir(), "inputs-\xff")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DAE_LOCATION_CACHE", dir)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/nodes":
			_, _ = io.WriteString(w, "socks5://127.0.0.1:1080\n")
		case "/module":
			_, _ = io.WriteString(w, "static module")
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	local := filepath.Join(dir, "nodes.txt")
	if err := os.WriteFile(local, []byte("socks5://127.0.0.1:1081\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.dae")
	text := fmt.Sprintf(`global { resource_cache: false }
subscription { '%s/nodes' '%s/missing' 'file:nodes.txt' }
plugins { fixture {} }
routing { fallback: direct }`, server.URL, server.URL)
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	definitions := map[string]plugin.Definition{"fixture": {
		Configure: func(plugin.Spec) (plugin.Factory, error) {
			return func(context.Context, plugin.Services) (plugin.Plugin, error) {
				t.Fatal("input preparation constructed a live plugin")
				return nil, nil
			}, nil
		},
		Resources: func(ctx context.Context, _ plugin.Spec, services plugin.Services) (plugin.Resources, error) {
			source, err := resource.Parse(server.URL+"/module", "")
			if err != nil {
				return plugin.Resources{}, err
			}
			value, _, err := (resource.Cache{Namespace: "fixture"}).Load(ctx, services.PrepareClient,
				resource.LoadOptions{Key: source.Location, MaxBytes: 1024}, func(read resource.ReadFunc) (string, error) {
					result, err := read(source, resource.ReadOptions{MaxBytes: 1024})
					return string(result.Data), err
				})
			if err == nil && value != "static module" {
				err = errors.New("unexpected module")
			}
			return plugin.Resources{Plan: new(plugin.Plan)}, err
		},
	}}
	prepare := func(ctx context.Context) *controlInputs {
		t.Helper()
		conf, _, err := config.LoadContext(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		conf.Global.SoMarkFromDae = 0 // Loopback-only, unprivileged fixture.
		inputs, err := loadControlInputs(ctx, conf, false, []string{dir}, path, nil)
		if err != nil {
			t.Fatal(err)
		}
		plugins, err := configurePlugins(conf, definitions)
		if err != nil {
			t.Fatal(err)
		}
		plane, err := control.NewUserspaceControlPlane(ctx, control.UserspaceResources{}, inputs.rules, inputs.nodes, conf, nil,
			func(client *http.Client) (control.PreparedMITM, error) {
				return loadMITM(ctx, conf, nil, client, nil, plugins, nil, []string{dir}, nil)
			})
		if err != nil {
			t.Fatal(err)
		}
		if err := plane.Close(); err != nil {
			t.Fatal(err)
		}
		return inputs
	}
	ctx, recorded := resource.WithInputRecording(t.Context())
	first := prepare(ctx)
	if requests.Load() != 3 || len(first.nodes) != 2 {
		t.Fatalf("requests=%d nodes=%d; wanted one module, two remote decisions and two accepted nodes", requests.Load(), len(first.nodes))
	}
	file, err := handoff.NewSealableFile("prepared-input-test")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := validateEmptyInputFile(file); err != nil {
		t.Fatal(err)
	}
	if err := recorded.Encode(file); err != nil {
		t.Fatal(err)
	}
	if _, err := readPreparedInputs(t.Context(), file); err == nil {
		t.Fatal("accepted unsealed prepared inputs")
	}
	if err := handoff.SealFile(file); err != nil {
		t.Fatal(err)
	}
	inputs, err := readPreparedInputs(t.Context(), file)
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	for _, name := range []string{path, local} {
		if err := os.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
	startup := &Startup{ctx: t.Context(), inputs: inputs}
	second := prepare(startup.InitializationContext())
	if requests.Load() != 3 || !first.equal(second) {
		t.Fatal("replay retried a skipped source or changed accepted inputs")
	}
	if resource.HasInputs(startup.ctx) {
		t.Fatal("runtime lifetime context retained input replay")
	}
	startup.inputs = nil
	if resource.HasInputs(startup.InitializationContext()) {
		t.Fatal("startup retained completed input replay")
	}
}
