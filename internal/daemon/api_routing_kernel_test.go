// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/vishvananda/netlink"
)

// Run alone in a fresh process and mount/network namespace with writable bpffs;
// daemon network namespace ownership lasts for the process lifetime.
func TestDaemonReloadRefreshesAPIAddressesKernel(t *testing.T) {
	if os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires isolated network/mount namespaces and BPF privileges")
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	oldAddress, _ := netlink.ParseAddr("192.0.2.1/32")
	newAddress, _ := netlink.ParseAddr("192.0.2.2/32")
	if err := netlink.AddrAdd(loopback, oldAddress); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = netlink.AddrDel(loopback, oldAddress)
		_ = netlink.AddrDel(loopback, newAddress)
	})
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	path := filepath.Join(dir, "config.dae")
	if err := os.WriteFile(path, []byte("global { disable_waiting_network:true }\napi { listen:'0.0.0.0:8081' }\nrouting { fallback:block }"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := InstallDefaultResolver(conf.Global.SoMarkFromDae, conf.Global.DNSResolver)
	if err != nil {
		t.Fatal(err)
	}
	store, err := settings.Open(filepath.Join(dir, "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	datapath := control.NewRuntime()
	app := &application{options: Options{ConfigFile: path}, conf: conf, datapath: datapath, resolver: resolver, settings: store, operations: newOperations()}
	certificates, err := prepareCertificates(conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.setCertificates(certificates)
	t.Cleanup(func() {
		app.managementAPI.Close()
		resolver.SetRoute(nil)
		_ = datapath.Close()
		_ = cleanupKernelResources()
	})
	app.inputs, err = loadControlInputs(t.Context(), conf, false, nil, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := app.preparePlane(t.Context(), conf, app.inputs, nil)
	if err != nil {
		t.Fatal(err)
	}
	serveKernelTestIngress(t, datapath, conf.Global.TproxyPort)
	if err := app.publishPlane(candidate, false); err != nil {
		t.Fatal(err)
	}
	old := app.plane
	if result, err := app.reload(t.Context(), false, false); err != nil || result != "No changes" || app.plane != old {
		t.Fatalf("unchanged API addresses replaced routing: %s, %v", result, err)
	}
	if err := netlink.AddrDel(loopback, oldAddress); err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(loopback, newAddress); err != nil {
		t.Fatal(err)
	}
	if result, err := app.reload(t.Context(), false, false); err != nil || app.plane != old {
		t.Fatalf("address-only reload rebuilt the control plane: %s, %v", result, err)
	}
	if current, err := app.plane.APIRoutingCurrent(); !current || err != nil {
		t.Fatalf("address refresh did not install current API addresses: %v, %v", current, err)
	}
	updated := app.plane
	if result, err := app.reload(t.Context(), false, false); err != nil || result != "No changes" || app.plane != updated {
		t.Fatalf("stable addresses did not return to no-op reload: %s, %v", result, err)
	}
	// Leave a previous generation retiring; address updates must not join its grace window.
	if err := os.WriteFile(path, []byte("global { disable_waiting_network:true }\napi { listen:'0.0.0.0:8081' }\nrouting { fallback:direct }"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.reload(t.Context(), false, false); err != nil || app.plane == updated {
		t.Fatalf("routing change did not publish a new generation: %v", err)
	}
	updated = app.plane
	server, inputs, host, lastReload := app.managementAPI, app.inputs, app.plane.MITMHost(), stats.DefaultStore.LastReload()
	if err := app.plane.RefreshAPIRouting(t.Context()); err != nil || app.plane != updated {
		t.Fatalf("unchanged network republished routing: %v", err)
	}
	select {
	case <-app.plane.APIAddressChanges():
	default:
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for i := range 4 {
		if i%2 == 0 {
			err = netlink.AddrAdd(loopback, oldAddress)
		} else {
			err = netlink.AddrDel(loopback, oldAddress)
		}
		if err != nil {
			t.Fatal(err)
		}
		for {
			select {
			case <-app.plane.APIAddressChanges():
				if err := app.plane.RefreshAPIRouting(ctx); err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("consecutive API address changes did not converge within five seconds")
			}
			current, err := app.plane.APIRoutingCurrent()
			if err != nil {
				t.Fatal(err)
			}
			if current {
				break
			}
		}
		if app.plane != updated || app.managementAPI != server || app.inputs != inputs || app.plane.MITMHost() != host || stats.DefaultStore.LastReload() != lastReload {
			t.Fatal("address refresh replaced runtime services or counted as a reload")
		}
	}
	if elapsed := time.Since(started); elapsed >= 5*time.Second {
		t.Fatalf("address updates exceeded the convergence deadline: %s", elapsed)
	} else {
		t.Logf("four address updates converged in %s while the previous generation was retiring", elapsed)
	}
}
