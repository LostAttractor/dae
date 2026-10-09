// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"google.golang.org/protobuf/proto"
)

type reloadWorker struct {
	starts atomic.Int32
	plan   plugin.Plan
}

func (p *reloadWorker) Plan() plugin.Plan { return p.plan }
func (p *reloadWorker) Run(ctx context.Context, _ *http.Client) error {
	p.starts.Add(1)
	<-ctx.Done()
	return nil
}

// Run alone in a fresh process and mount/network namespace with writable bpffs:
// the daemon owns a process-lifetime netns. Exercise the real loader and
// publication boundary, including the no-op/abort decision.
func TestDaemonDifferentialReloadKernel(t *testing.T) {
	if os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires isolated network/mount namespaces and BPF privileges")
	}
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	t.Setenv("DAE_LOCATION_ASSET", dir)
	writeGeodata := func(subnet, domain, unused string) {
		t.Helper()
		prefix := netip.MustParsePrefix(subnet)
		for name, data := range map[string]proto.Message{
			"geoip.dat": &geodata.GeoIPList{Entry: []*geodata.GeoIP{{CountryCode: "reload-test", Cidr: []*geodata.CIDR{{Ip: prefix.Addr().AsSlice(), Prefix: uint32(prefix.Bits())}}}}},
			"geosite.dat": &geodata.GeoSiteList{Entry: []*geodata.GeoSite{
				{CountryCode: "reload-test", Domain: []*geodata.Domain{{Type: geodata.Domain_Full, Value: domain}}},
				{CountryCode: "unused", Domain: []*geodata.Domain{{Type: geodata.Domain_Full, Value: unused}}},
			}},
		} {
			data, err := proto.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeGeodata("198.51.100.0/24", "old.example", "unused.example")
	plan := plugin.Plan{Destinations: routing.DestinationRewrites{{
		Filter: []*config_parser.Function{
			{Name: "dip", Params: []*config_parser.Param{{Key: "geoip", Val: "reload-test"}}},
			{Name: "domain", Params: []*config_parser.Param{{Key: "geosite", Val: "reload-test"}}},
			{Name: "dport", Params: []*config_parser.Param{{Val: "443"}}},
		},
		To: []netip.Addr{netip.MustParseAddr("192.0.2.20")},
	}}}
	path := filepath.Join(dir, "config.dae")
	write := func(body string) *config.Config {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		conf, _, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return conf
	}
	text := "global { disable_waiting_network:true }\nplugins { fixture {} }\nrouting { fallback:direct }"
	conf := write(text)
	resourcePath := filepath.Join(dir, "resource")
	if err := os.WriteFile(resourcePath, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	var built atomic.Int32
	definitions := map[string]plugin.Definition{"fixture": {Configure: func(plugin.Spec) (plugin.Factory, error) {
		return func(context.Context, plugin.Services) (plugin.Plugin, error) {
			built.Add(1)
			return &reloadWorker{plan: plan}, nil
		}, nil
	}, Resources: func(context.Context, plugin.Spec, plugin.Services) (plugin.Resources, error) {
		content, err := os.ReadFile(resourcePath)
		return plugin.Resources{Key: string(content)}, err
	}}}
	resolver, err := netutils.InstallDefaultResolver(conf.Global.SoMarkFromDae, conf.Global.DNSResolver)
	if err != nil {
		t.Fatal(err)
	}
	store, err := settings.Open(filepath.Join(dir, "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	datapath := control.NewRuntime()
	client, closeClient := datapath.NewWorkerClient()
	app := &application{options: Options{ConfigFile: path}, conf: conf, datapath: datapath, resolver: resolver, settings: store, definitions: definitions, workerClient: client}
	t.Cleanup(func() { resolver.SetRoute(nil); _ = datapath.Close(); closeClient(); _ = cleanupKernelResources() })
	plugins, err := configurePlugins(conf, definitions)
	if err != nil {
		t.Fatal(err)
	}
	app.inputs, err = loadControlInputs(t.Context(), conf, false, nil, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.plane, err = newControlPlane(t.Context(), datapath, conf, app.inputs, store, func(download *http.Client) (control.PreparedMITM, error) {
		return loadMITM(t.Context(), conf, download, client, plugins, nil, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := datapath.Publish(app.plane, false); err != nil {
		t.Fatal(err)
	}
	original, host := app.plane, app.plane.MITMHost()
	if result, err := app.reload(t.Context(), false, false); err != nil || result != "No changes" {
		t.Fatalf("unchanged reload: %s, %v", result, err)
	}
	if app.plane != original || app.plane.MITMHost() != host || built.Load() != 1 {
		t.Fatal("unchanged reload reconstructed running resources")
	}
	write("global { disable_waiting_network:true api_key:'new-key' log_level:debug }\nplugins { fixture {} }\nrouting { fallback:direct }")
	if _, err := app.reload(t.Context(), false, false); err != nil {
		t.Fatal(err)
	}
	if app.plane != original || app.plane.MITMHost() != host {
		t.Fatal("management edit rebuilt datapath/plugins")
	}
	if err := os.WriteFile(resourcePath, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.reload(t.Context(), false, false); err != nil {
		t.Fatalf("resource change: %v", err)
	}
	if app.plane != original || app.plane.MITMHost().SameInstances(host) || built.Load() != 2 {
		t.Fatal("resource change did not replace only the plugin")
	}
	host = app.plane.MITMHost()
	if err := os.Remove(resourcePath); err != nil {
		t.Fatal(err)
	}
	if _, err := app.reload(t.Context(), false, false); err == nil {
		t.Fatal("missing external resource accepted as deletion")
	}
	if app.plane != original || app.plane.MITMHost() != host {
		t.Fatal("failed resource refresh changed active resources")
	}
	if err := os.WriteFile(resourcePath, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	writeGeodata("203.0.113.0/24", "new.example", "unused.example")
	if _, err := app.reload(t.Context(), false, false); err != nil {
		t.Fatalf("plugin geodata refresh: %v", err)
	}
	if app.plane == original || !app.plane.MITMHost().SameInstances(host) || built.Load() != 2 {
		t.Fatal("plugin geodata change failed to replace routing while retaining instances")
	}
	original, host = app.plane, app.plane.MITMHost()
	writeGeodata("203.0.113.0/24", "new.example", "changed-unused.example")
	if result, err := app.reload(t.Context(), false, false); err != nil || result != "No changes" {
		t.Fatalf("unused geodata change: %s, %v", result, err)
	}
	if app.plane != original || app.plane.MITMHost() != host {
		t.Fatal("unchanged effective geodata rebuilt resources")
	}
	for _, file := range []string{"geoip.dat", "geosite.dat"} {
		for _, corrupt := range []bool{false, true} {
			writeGeodata("203.0.113.0/24", "new.example", "unused.example")
			path := filepath.Join(dir, file)
			if corrupt {
				if err := os.WriteFile(path, []byte{0xff}, 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if _, err := app.reload(t.Context(), false, false); err == nil {
				t.Fatalf("accepted unavailable plugin geodata %s (corrupt=%v)", file, corrupt)
			}
			if app.plane != original || app.plane.MITMHost() != host {
				t.Fatal("failed geodata refresh changed active resources")
			}
		}
	}
	writeGeodata("203.0.113.0/24", "new.example", "unused.example")
	if err := os.WriteFile(path, []byte("invalid configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.reload(t.Context(), false, false); err == nil {
		t.Fatal("invalid reload succeeded")
	}
	if app.plane != original {
		t.Fatal("failed reload replaced the active plane")
	}
	write(text)
	if _, err := app.reload(t.Context(), false, true); err != nil {
		t.Fatalf("explicit no-change abort: %v", err)
	}
	if app.plane == original || built.Load() != 2 || !app.plane.MITMHost().SameInstances(host) {
		t.Fatal("abort failed to replace ingress while preserving plugin instances")
	}
	if err := os.Remove(resourcePath); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"geoip.dat", "geosite.dat"} {
		if err := os.Remove(filepath.Join(dir, file)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte("invalid configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.reload(t.Context(), true, true); err != nil {
		t.Fatalf("suspend did not use accepted resources: %v", err)
	}
	if built.Load() != 2 || !app.plane.MITMHost().SameInstances(host) {
		t.Fatal("suspend reconstructed accepted plugin state")
	}
}
