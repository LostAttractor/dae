// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	jsonv1 "encoding/json"
	jsonv2 "encoding/json/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/internal/apiserver"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestPluginConfigurationStatusWithoutHost(t *testing.T) {
	plane := &ControlPlane{}
	compiled := []string{"fixture"}
	specs := config.Plugins{{Name: "future", Type: "not-compiled", Config: &config_parser.Section{Name: "private-credential"}}}
	plane.SetPluginConfiguration(specs, compiled)
	compiled[0], specs[0].Name = "mutated", "mutated"
	status := plane.MITMStatus()
	if !reflect.DeepEqual(status.CompiledPlugins, []string{"fixture"}) || len(status.Plugins) != 1 {
		t.Fatalf("lost accepted configuration: %+v", status)
	}
	p := status.Plugins[0]
	if p.ID != "future" || p.Type != "not-compiled" || p.Enabled || p.State != "disabled" || p.HTTPActive || p.HTTPReason != "disabled" || p.DeclaredScopes != 0 || p.Scopes != 0 || len(p.Details) != 0 {
		t.Fatalf("disabled status: %+v", p)
	}
	wire, err := jsonv2.Marshal(status)
	if err != nil || strings.Contains(string(wire), "private-credential") {
		t.Fatalf("configuration leaked: %s, %v", wire, err)
	}
	status.CompiledPlugins[0], status.Plugins[0].ID = "mutated", "mutated"
	if next := plane.MITMStatus(); next.CompiledPlugins[0] != "fixture" || next.Plugins[0].ID != "future" {
		t.Fatalf("snapshot mutation changed accepted status: %+v", next)
	}
	plane.SetPluginConfiguration(nil, nil)
	wire, err = jsonv2.Marshal(plane.MITMStatus())
	if err != nil || !strings.Contains(string(wire), `"compiled_plugins":[]`) {
		t.Fatalf("empty compiled list missing: %s, %v", wire, err)
	}
}

func TestReplaceMITMPublishesConfigurationOnlyAfterActivation(t *testing.T) {
	plane := &ControlPlane{core: &controlPlaneCore{bpf: &BPFState{}}, ctx: t.Context()}
	plane.SetPluginConfiguration(config.Plugins{{Name: "old", Type: "uncompiled"}}, []string{"test"})
	before := plane.MITMStatus()
	rejected := controlTestHost(t, &controlTestPlugin{}, nil)
	if err := rejected.Close(); err != nil {
		t.Fatal(err)
	}
	plugins := config.Plugins{{Name: "test", Type: "test", Enabled: true}, {Name: "new", Type: "uncompiled"}}
	if err := plane.ReplaceMITM(PreparedMITM{Host: rejected}, plugins); err == nil {
		t.Fatal("closed candidate was accepted")
	}
	if after := plane.MITMStatus(); !reflect.DeepEqual(after, before) || plane.MITMHost() != nil {
		t.Fatalf("failed activation published status: %+v", after)
	}
	host := controlTestHost(t, &controlTestPlugin{}, nil)
	stop, ready := make(chan struct{}), make(chan struct{})
	var readers sync.WaitGroup
	readers.Go(func() {
		close(ready)
		for {
			select {
			case <-stop:
				return
			default:
			}
			status := plane.MITMStatus()
			old := len(status.Plugins) == 1 && status.Plugins[0].ID == "old" && !status.Plugins[0].Enabled
			current := len(status.Plugins) == 2 && status.Plugins[0].ID == "test" && status.Plugins[0].State == "active" && status.Plugins[1].ID == "new"
			if !old && !current {
				t.Errorf("mixed host/configuration generation: %+v", status)
				return
			}
		}
	})
	defer func() { close(stop); readers.Wait() }()
	<-ready
	if err := plane.ReplaceMITM(PreparedMITM{Host: host}, plugins); err != nil {
		t.Fatal(err)
	}
	status := plane.MITMStatus()
	if plane.MITMHost() != host || !reflect.DeepEqual(status.CompiledPlugins, []string{"test"}) || len(status.Plugins) != 2 || status.Plugins[0].State != "active" || !status.Plugins[0].Enabled || status.Plugins[1].ID != "new" || status.Plugins[1].State != "disabled" {
		t.Fatalf("host and accepted envelope disagree: %+v", status)
	}
}

func TestPluginStatusPreservesSystemInstances(t *testing.T) {
	host := controlTestHost(t, &controlTestPlugin{}, nil)
	plane := &ControlPlane{mitmHost: host}
	plane.SetPluginConfiguration(config.Plugins{{Name: "disabled", Type: "future"}}, []string{"compiled"})
	status := plane.MITMStatus()
	if len(status.Plugins) != 2 || status.Plugins[0].ID != "disabled" || status.Plugins[1].ID != "test" || !status.Plugins[1].Enabled {
		t.Fatalf("system instance was dropped: %+v", status)
	}
}

func TestAPIPluginsFollowPublishedPlane(t *testing.T) {
	server := &apiserver.Server{}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if err := localca.Generate(cert, key, "status API", time.Hour); err != nil {
		t.Fatal(err)
	}
	authority, err := localca.Load(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	firstPlugin := mitmRoutingPlugin("one.example")
	firstPlugin.details = map[string]string{"generation": "first"}
	first := &ControlPlane{mitmHost: controlTestHost(t, firstPlugin, authority)}
	secondPlugin := mitmRoutingPlugin("two.example", "three.example")
	secondPlugin.details = map[string]string{"generation": "second"}
	second := &ControlPlane{mitmHost: controlTestHost(t, secondPlugin, authority)}
	for _, test := range []struct {
		plane      *ControlPlane
		enabled    bool
		generation string
	}{
		{first, true, "first"},
		{nil, false, ""},
		{second, true, "second"},
		{&ControlPlane{}, false, ""},
	} {
		if test.plane == nil {
			server.SetHandler(nil)
		} else {
			server.SetHandler(test.plane.apiHandler("test", nil, nil, nil))
		}
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "http://unix/api/status", nil)
		request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, &net.UnixAddr{Name: "dae.sock", Net: "unix"}))
		server.ServeHTTP(response, request)
		if test.plane == nil {
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("unpublished plane returned %d", response.Code)
			}
			continue
		}
		if response.Code != http.StatusOK {
			t.Fatalf("status: %d %s", response.Code, response.Body)
		}
		var snapshot api.StatusSnapshot
		if err := jsonv2.Unmarshal(response.Body.Bytes(), &snapshot, jsonv1.FormatDurationAsNano(true)); err != nil {
			t.Fatal(err)
		}
		if (len(snapshot.Plugins) > 0) != test.enabled {
			t.Fatalf("plugin status enabled=%v, want %v", len(snapshot.Plugins) > 0, test.enabled)
		}
		if !test.enabled {
			continue
		}
		if len(snapshot.Plugins) != 1 {
			t.Fatalf("unexpected plugins: %+v", snapshot.Plugins)
		}
		status := snapshot.Plugins[0]
		var details map[string]string
		if err := jsonv2.Unmarshal(status.Details, &details); err != nil {
			t.Fatal(err)
		}
		if status.ID != "test" || status.Type != "test" || status.State != "prepared" || status.Scopes != 1 || details["generation"] != test.generation {
			t.Fatalf("status retained another plane's plugin: %+v details=%v", status, details)
		}
	}
}

// A status poll waits for plugin reports without holding mitmMu: a reload
// publishing its configuration is not queued behind it.
func TestMITMStatusReportsOutsideTheLock(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	extension := &blockingReportPlugin{entered: entered, release: release}
	plane := &ControlPlane{}
	plane.mitmHost = controlTestHost(t, extension, nil)
	polled := make(chan api.PluginStatus, 1)
	go func() { polled <- plane.MITMStatus() }()
	<-entered
	published := make(chan struct{})
	go func() {
		plane.SetPluginConfiguration(config.Plugins{{Name: "test", Type: "test", Enabled: true}}, nil)
		close(published)
	}()
	select {
	case <-published:
	case <-time.After(time.Second):
		t.Fatal("configuration waited for a plugin status report")
	}
	close(release)
	if status := <-polled; len(status.Plugins) != 1 || status.Plugins[0].ID != "test" {
		t.Fatalf("status = %+v", status)
	}
}

type blockingReportPlugin struct {
	controlTestPlugin
	once             sync.Once
	entered, release chan struct{}
}

func (p *blockingReportPlugin) Report() any {
	p.once.Do(func() { close(p.entered) })
	<-p.release
	return nil
}
