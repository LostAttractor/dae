// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/common/netutils"
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
	if err := os.WriteFile(path, []byte("global { api_port:8081 disable_waiting_network:true }\nrouting { fallback:block }"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := netutils.InstallDefaultResolver(conf.Global.SoMarkFromDae, conf.Global.DNSResolver)
	if err != nil {
		t.Fatal(err)
	}
	store, err := settings.Open(filepath.Join(dir, "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	datapath := control.NewRuntime()
	app := &application{options: Options{ConfigFile: path}, conf: conf, datapath: datapath, resolver: resolver, settings: store}
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
	app.plane, err = newControlPlane(t.Context(), datapath, conf, app.inputs, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := datapath.Publish(app.plane, false); err != nil {
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
	if result, err := app.reload(t.Context(), false, false); err != nil || app.plane == old {
		t.Fatalf("address change reused stale API routing: %s, %v", result, err)
	}
	if current, err := app.plane.APIRoutingCurrent(); !current || err != nil {
		t.Fatalf("replacement did not install current API addresses: %v, %v", current, err)
	}
	updated := app.plane
	if result, err := app.reload(t.Context(), false, false); err != nil || result != "No changes" || app.plane != updated {
		t.Fatalf("stable addresses did not return to no-op reload: %s, %v", result, err)
	}
}
