// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/miekg/dns"
)

func TestRuntimeDeviceStoreIsolation(t *testing.T) {
	for _, disk := range []bool{false, true} {
		t.Run(fmt.Sprint(disk), func(t *testing.T) {
			var path string
			if disk {
				path = filepath.Join(t.TempDir(), "store.json")
			}
			r := testRuntime(t, RuntimeOptions{StorePath: path})
			a, b := testDeviceMAC, [6]byte{2, 0, 0, 0, 0, 2}
			run := func(mac [6]byte, source string) {
				t.Helper()
				result, err := r.Runtime.Run(t.Context(), source, Invocation{Scope: testMACScope(mac), ScriptPath: "shared.js", BodyMemory: r.budget, BodyLimit: 1 << 20})
				result.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			result, err := r.Run(t.Context(), `if (!$persistentStore.write("local", "cookie") || !$persistentStore.write("default-local")) throw Error("write local"); $done();`, Invocation{Scope: testLocalScope, ScriptPath: "shared.js"})
			result.Close()
			if err != nil {
				t.Fatal(err)
			}
			run(a, `if ($persistentStore.read("cookie") !== null || $persistentStore.read() !== null) throw Error("read local"); if (!$persistentStore.write("A", "cookie") || !$persistentStore.write("default-A")) throw Error("write A"); $done();`)
			run(b, `if ($persistentStore.read("cookie") !== null || $persistentStore.read() !== null) throw Error("read A"); if (!$persistentStore.write("B", "cookie")) throw Error("write B"); $done();`)
			run(a, `if ($persistentStore.read("cookie") !== "A" || $persistentStore.read() !== "default-A") throw Error("lost A"); if (!$persistentStore.write(null, "cookie")) throw Error("delete A"); $done();`)
			run(b, `if ($persistentStore.read("cookie") !== "B") throw Error("delete crossed device"); $done();`)
			for _, mac := range [][6]byte{{}, {1, 0, 0, 0, 0, 1}, {255, 255, 255, 255, 255, 255}} {
				run(mac, `if ($persistentStore.read("cookie") !== null || $persistentStore.write("anonymous", "cookie") !== false || $persistentStore.write(null, "cookie") !== false) throw Error("anonymous store access"); $done();`)
			}
			if len(r.data.values) != 3 {
				t.Fatalf("unexpected store buckets: %v", r.data.values)
			}
			run(a, `if (!$persistentStore.write(null)) throw Error("delete default"); $done();`)
			if len(r.data.values) != 2 {
				t.Fatal("empty device bucket retained")
			}
			if got, err := r.data.read(t.Context(), testLocalScope, "cookie"); err != nil || got != "local" {
				t.Fatalf("device changed local store: %v %v", got, err)
			}
			if disk {
				other := testRuntime(t, RuntimeOptions{StorePath: path})
				if got, err := other.data.read(t.Context(), testMACScope(b), "cookie"); err != nil || got != "B" {
					t.Fatalf("reload lost device store: %v %v", got, err)
				}
				if got, err := other.data.read(t.Context(), testLocalScope, "cookie"); err != nil || got != "local" {
					t.Fatalf("reload lost local store: %v %v", got, err)
				}
			}
		})
	}
}

func TestDeviceStoreCapacityIsSharedAcrossDevices(t *testing.T) {
	store, err := openRuntimeStore("")
	if err != nil {
		t.Fatal(err)
	}
	value := strings.Repeat("x", maxStoreValueSize)
	for i := range 15 {
		store.values[fmt.Sprintf("02:00:00:00:00:%02x", i+1)] = map[string]string{"value": value}
	}
	mac := [6]byte{2, 0, 0, 0, 0, 16}
	if store.write(t.Context(), testMACScope(mac), "value", value, false) {
		t.Fatal("per-device capacity bypassed the instance limit")
	}
	if len(store.values) != 15 {
		t.Fatal("rejected write changed device buckets")
	}
	if !store.write(t.Context(), testMACScope(mac), "value", "small", false) {
		t.Fatal("rejected write prevented a later bounded write")
	}
}

func TestDeviceStoreRejectsInvalidSnapshot(t *testing.T) {
	for _, contents := range []string{
		`{"cookie":"unassigned"}`,
		`{"00:00:00:00:00:00":{"cookie":"bad"}}`,
		`{"01:00:00:00:00:01":{"cookie":"bad"}}`,
		`{"02:00:00:00:00:01":null}`,
		`{"local":null}`,
		`{"unknown":{"cookie":"bad"}}`,
		`{"02:00:00:00:00:01":{"cookie":3}}`,
	} {
		t.Run(contents, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.json")
			if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := openRuntimeStore(path); err == nil {
				t.Fatal("accepted invalid snapshot")
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != contents {
				t.Fatalf("invalid snapshot was modified: %s %v", got, err)
			}
		})
	}
}

func TestHTTPDeviceIdentitySharedByRequestAndResponse(t *testing.T) {
	module := moduleScopeModule(t, "http", "example.com", `[Script]
request=type=http-request,pattern=.,script-path=request.js
response=type=http-response,pattern=.,script-path=response.js`, map[string]string{
		"request":  `$persistentStore.write($request.headers.cookie, "cookie"); $done();`,
		"response": `$done({headers:{"X-Cookie":String($persistentStore.read("cookie"))}});`,
	})
	e := moduleScopeEngine(t, module)
	e.options.IsolateLAN = true
	var capture proxyTraceCapture
	e.options.Logger = capture.logger()
	devices := newTestDevices()
	e.options.Devices = devices
	calls := 0
	devices.identify = func(_ context.Context, ip netip.Addr, mac [6]byte) [6]byte {
		calls++
		if ip == netip.MustParseAddr("192.0.2.99") {
			return [6]byte{}
		}
		return mac
	}
	a, b := testDeviceMAC, [6]byte{2, 0, 0, 0, 0, 2}
	for _, test := range []struct {
		ip           string
		mac          [6]byte
		cookie, want string
	}{
		{"192.0.2.1", a, "A", "A"},
		{"192.0.2.2", b, "B", "B"},
		{"2001:db8::1", a, "A-v6", "A-v6"},
		{"192.0.2.99", a, "spoofed", "null"},
	} {
		request := httptest.NewRequest("GET", "https://example.com/", nil)
		request.Header.Set("Cookie", test.cookie)
		request.Header.Set("X-Device-MAC", testDeviceName)
		flow := plugin.Flow{Host: "example.com", Port: 443, Source: netip.AddrPortFrom(netip.MustParseAddr(test.ip), 12345), SourceOrigin: plugin.SourceLAN, SourceMAC: test.mac}
		response, err := e.Wrap(flow, func(exchange *plugin.Exchange) (*plugin.Response, error) {
			return exchange.NewResponse(&http.Response{StatusCode: 200, Request: exchange.Request.Head, Header: make(http.Header), Body: http.NoBody}), nil
		})(&plugin.Exchange{Request: plugin.NewRequest(request, e.options.BodyMemory), Client: http.DefaultClient})
		if err != nil {
			t.Fatal(err)
		}
		response.Close()
		if got := response.Head.Header.Get("X-Cookie"); got != test.want {
			t.Fatalf("device=%v response cookie=%q want=%q", test.mac, got, test.want)
		}
		wantMAC := net.HardwareAddr(test.mac[:]).String()
		if test.want == "null" {
			wantMAC = ""
		}
		capture.mu.Lock()
		events := capture.trace
		capture.trace = nil
		capture.mu.Unlock()
		for _, event := range events {
			if (event["event"] == "script_start" || event["event"] == "script_end") && event["mac"] != wantMAC {
				t.Fatalf("script trace identity: %v", event)
			}
		}
	}
	if calls != 4 {
		t.Fatalf("request/response did not share identity: %d queries", calls)
	}
	for mac, want := range map[[6]byte]string{a: "A-v6", b: "B"} {
		if got, err := e.options.Runtime.data.read(t.Context(), testMACScope(mac), "cookie"); err != nil || got != want {
			t.Fatalf("HTTP identity isolation: %v %v", got, err)
		}
	}
}

func TestAnonymousDNSScriptBypassesCache(t *testing.T) {
	module := moduleScopeModule(t, "dns", "", "[Host]\nscript.test=script:answer\n[Script]\nanswer=type=dns,script-path=answer.js", map[string]string{"answer": `
if ($persistentStore.read("secret") !== null || $persistentStore.write("bad", "secret")) throw Error("anonymous storage");
$done({addresses:["192.0.2.1"],ttl:60});`})
	e := moduleScopeEngine(t, module)
	e.options.IsolateLAN = true
	var capture proxyTraceCapture
	e.options.Logger = capture.logger()
	devices := newTestDevices()
	devices.identify = func(_ context.Context, _ netip.Addr, _ [6]byte) [6]byte { return [6]byte{} }
	e.options.Devices = devices
	if !e.options.Runtime.data.write(t.Context(), testDeviceScope, "secret", "private", false) || !e.options.Runtime.data.write(t.Context(), testLocalScope, "secret", "local", false) {
		t.Fatal("seed")
	}
	handler := e.WrapDNS(func(context.Context, *plugin.DNSExchange) (*plugin.DNSResponse, error) {
		t.Fatal("unexpected DNS fallback")
		return nil, nil
	})
	query := hostDNSRequest(t, "script.test.", dns.TypeA)
	query.SourceOrigin, query.SourceMAC = plugin.SourceLAN, testDeviceMAC
	for range 2 {
		response, err := handler(t.Context(), query)
		if err != nil || response.Cached {
			t.Fatalf("anonymous DNS cached: %+v %v", response, err)
		}
	}
}
