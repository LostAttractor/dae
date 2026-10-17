// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

func TestStatusWithoutInstancesKeepsBodyBudget(t *testing.T) {
	budget := membuffer.NewBudget(4096)
	host, err := New(Options{BodyMemory: budget})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	status := host.Status()
	if len(status.Plugins) != 0 || status.BufferMemory != api.BufferMemoryStatus(budget.Status()) {
		t.Fatalf("empty host lost process budget: %+v", status)
	}
}

type reportingPlugin struct {
	testPlugin
	Secret string
	detail any
}

func (p *reportingPlugin) Report() any { return p.detail }

func TestLoadIndependentFactoriesAndReports(t *testing.T) {
	section := &config_parser.Section{Name: "example"}
	client := &http.Client{}
	for _, label := range []string{"first", "second"} {
		definitions := map[string]plugin.Definition{
			"example": testDefinition(func(_ context.Context, spec plugin.Spec, services plugin.Services) (plugin.Plugin, error) {
				if spec.Config != section || services.BaseDir != "/fixture" || services.PrepareClient != client || services.Logger.Data["plugin_instance"] != "instance" {
					t.Fatal("setup did not receive instance-local services")
				}
				return &reportingPlugin{Secret: "private-credential", detail: map[string]string{"label": label}}, nil
			}),
		}
		host, err := loadTestPlugins(t.Context(), definitions, []plugin.Spec{{ID: "instance", Type: "example", Config: section}}, Options{}, plugin.Services{BaseDir: "/fixture", PrepareClient: client})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = host.Close() })
		for _, state := range []string{"prepared", "active", "draining"} {
			switch state {
			case "active":
				err = host.Start(context.Background())
			case "draining":
				err = host.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			status := host.Status()
			if len(status.Plugins) != 1 || status.Plugins[0].State != state || string(status.Plugins[0].Details) != `{"label":"`+label+`"}` {
				t.Fatalf("incorrect instance status: %+v", status)
			}
			if memory := status.BufferMemory; memory != api.BufferMemoryStatus(bodyMemory.Status()) {
				t.Fatalf("lost process buffer budget: %+v", memory)
			}
			wire, err := json.Marshal(status)
			if err != nil || strings.Contains(string(wire), "private-credential") {
				t.Fatalf("status serialized implementation state: %s, %v", wire, err)
			}
		}
	}
}
