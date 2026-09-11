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
)

type reportingPlugin struct {
	testPlugin
	Secret string
	detail any
}

func (p *reportingPlugin) Report() any { return p.detail }

func TestLoadIndependentSetupTablesAndReports(t *testing.T) {
	section := &config_parser.Section{Name: "example"}
	client := &http.Client{}
	for _, label := range []string{"first", "second"} {
		definitions := map[string]plugin.Definition{
			"example": {Setup: func(_ context.Context, spec plugin.Spec, services plugin.Services) (plugin.Plugin, error) {
				if spec.Config != section || services.BaseDir != "/fixture" || services.PrepareClient != client || services.Logger.Data["plugin_instance"] != "instance" {
					t.Fatal("setup did not receive instance-local services")
				}
				return &reportingPlugin{Secret: "private-credential", detail: map[string]string{"label": label}}, nil
			}},
		}
		host, err := Load(context.Background(), definitions, []plugin.Spec{{ID: "instance", Type: "example", Config: section}}, Options{}, plugin.Services{BaseDir: "/fixture", PrepareClient: client})
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
			if len(status) != 1 || status[0].State != state || string(status[0].Details) != `{"label":"`+label+`"}` {
				t.Fatalf("incorrect instance status: %+v", status)
			}
			if memory := status[0].BufferMemory; memory == nil || *memory != api.BufferMemoryStatus(plugin.BodyMemory.Status()) {
				t.Fatalf("lost process buffer budget: %+v", memory)
			}
			wire, err := json.Marshal(status)
			if err != nil || strings.Contains(string(wire), "private-credential") {
				t.Fatalf("status serialized implementation state: %s, %v", wire, err)
			}
		}
	}
}
