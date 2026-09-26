// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
)

type storageTestPlugin struct{ storage plugin.Storage }

func (*storageTestPlugin) Plan() plugin.Plan { return plugin.Plan{} }

func TestLoadScopesPluginStorage(t *testing.T) {
	var prepared []*storageTestPlugin
	definition := testDefinition(func(_ context.Context, _ plugin.Spec, services plugin.Services) (plugin.Plugin, error) {
		p := &storageTestPlugin{storage: services.Storage}
		prepared = append(prepared, p)
		return p, nil
	})
	definitions := map[string]plugin.Definition{"fixture": definition, "other": definition}
	services := plugin.Services{BaseDir: t.TempDir()}
	load := func(typ, id string) {
		t.Helper()
		host, err := loadTestPlugins(t.Context(), definitions, []plugin.Spec{{Type: typ, ID: id}}, Options{}, services)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = host.Close() })
	}
	load("fixture", "fixture")
	if err := prepared[0].storage.Put("state", []byte("saved")); err != nil {
		t.Fatal(err)
	}
	load("fixture", "fixture")
	if got, err := prepared[1].storage.Get("state"); err != nil || string(got) != "saved" {
		t.Fatalf("reload did not reuse storage: %q, %v", got, err)
	}
	load("fixture", "two")
	load("other", "fixture")
	for _, p := range prepared[2:] {
		if _, err := p.storage.Get("state"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("storage crossed type/instance boundary: %v", err)
		}
	}
	services.BaseDir = ""
	load("fixture", "memory")
	if prepared[len(prepared)-1].storage != nil {
		t.Fatal("empty base directory enabled persistence")
	}
}
