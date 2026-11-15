// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/persist"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/miekg/dns"
)

func TestDNSScriptCacheStoreMigration(t *testing.T) {
	for _, syncFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(syncFailure), func(t *testing.T) {
			module := moduleScopeModule(t, "dns", "", "[Host]\nscript.test=script:answer\n[Script]\nanswer=type=dns,script-path=answer.js", map[string]string{
				"answer": `$done({addresses:[$persistentStore.read("ip") || "192.0.2.200"],ttl:60});`,
			})
			path := filepath.Join(t.TempDir(), "store.json")
			r := testRuntime(t, RuntimeOptions{StorePath: path})
			reloaded := testRuntime(t, RuntimeOptions{StorePath: path})
			engines := []*Engine{
				newTestEngine(t, EngineOptions{Modules: []*Module{module}, Runtime: r.Runtime, IsolateLAN: true, Devices: newTestDevices()}),
				newTestEngine(t, EngineOptions{Modules: []*Module{module}, Runtime: reloaded.Runtime, IsolateLAN: true, Devices: newTestDevices()}),
			}
			if !r.data.write(t.Context(), testDeviceScope, "ip", "192.0.2.1", false) || !r.data.write(t.Context(), testLocalScope, "ip", "192.0.2.9", false) {
				t.Fatal("seed")
			}
			to, other := [6]byte{2, 0, 0, 0, 0, 2}, [6]byte{2, 0, 0, 0, 0, 3}
			terminal := func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
				t.Fatal("unexpected DNS fallback")
				return nil, nil
			}
			query := func(e *Engine, scope ScriptScope, cached bool, want string) {
				t.Helper()
				request := hostDNSRequest(t, "script.test.", dns.TypeA)
				request.SourceMAC = scope.MAC
				request.SourceOrigin = plugin.SourceLAN
				if scope == testLocalScope {
					request.SourceOrigin = plugin.SourceLocal
				}
				response, err := e.WrapDNS(terminal)(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				if response.Cached != cached || response.MessageCopy().Answer[0].(*dns.A).A.String() != want {
					t.Fatalf("scope=%v cached=%t answer=%v want=%s", scope, response.Cached, response.MessageCopy().Answer, want)
				}
			}
			for _, e := range engines {
				for _, test := range []struct {
					scope ScriptScope
					ip    string
				}{
					{testLocalScope, "192.0.2.9"}, {testDeviceScope, "192.0.2.1"}, {testMACScope(to), "192.0.2.200"}, {testMACScope(other), "192.0.2.200"},
				} {
					query(e, test.scope, false, test.ip)
					query(e, test.scope, true, test.ip)
				}
			}
			request := hostDNSRequest(t, "script.test.", dns.TypeA)
			oldKey := dnsScriptKey(&engines[0].options.Modules[0].Scripts[0], request)
			oldKey.scope, oldKey.generation = testMACScope(to), r.data.generation.Load()
			if syncFailure {
				r.data.syncDir = func(string) error { return errors.New("directory sync failed") }
			}
			count, err := r.data.migrate(t.Context(), testDeviceMAC, to)
			if count != 1 || !persist.Published(err) || (err != nil) != syncFailure {
				t.Fatalf("migration: %d %v", count, err)
			}
			// Simulate a DNS result published after migration, although Run already returned.
			engines[0].dnsCache.put(oldKey, []netip.Addr{netip.MustParseAddr("198.51.100.99")}, 60, time.Now())
			for _, e := range engines {
				query(e, testLocalScope, true, "192.0.2.9")
				query(e, testDeviceScope, false, "192.0.2.200")
				query(e, testMACScope(to), false, "192.0.2.1")
				query(e, testMACScope(to), true, "192.0.2.1")
				query(e, testMACScope(other), false, "192.0.2.200")
			}
		})
	}
}
