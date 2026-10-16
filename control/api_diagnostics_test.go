// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	apiclient "github.com/daeuniverse/dae/api/client"
)

func TestDiagnosticsAPIAndClientAdministration(t *testing.T) {
	c := diagnosticPlane(t, "client(work) -> block", "")
	c.apiKey = "secret"
	server := httptest.NewServer(c.apiHandler("test", testClientIngress, nil))
	defer server.Close()
	admin, err := apiclient.New(apiclient.Options{Endpoint: server.URL, APIKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	guest, err := apiclient.New(apiclient.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	mac := "02:00:00:00:00:10"
	if _, err := guest.SetClientMember(t.Context(), "work", mac, true); err == nil {
		t.Fatal("guest changed arbitrary MAC")
	}
	group, err := admin.SetClientMember(t.Context(), "work", mac, true)
	if err != nil || !slices.Contains(group.Members, mac) {
		t.Fatal(group, err)
	}
	device, err := admin.ManagedDevice(t.Context(), mac)
	if err != nil || len(device.Sets) != 1 || !device.Sets[0].Joined {
		t.Fatal(device, err)
	}
	request := diagnosticRequest()
	response, err := admin.Explain(t.Context(), request, false)
	if err != nil || response.Current.Decision.Verdict != "drop" {
		t.Fatal(response, err)
	}
	if _, err := guest.Explain(t.Context(), request, false); err == nil {
		t.Fatal("guest used administrator explanation")
	}
	if _, err := guest.Explain(t.Context(), request, true); err == nil {
		t.Fatal("device endpoint accepted forged identity")
	}
	request.Context = api.DiagnosticContext{}
	if _, err := guest.Explain(t.Context(), request, true); err == nil {
		t.Fatal("LAN guest used current-device diagnostics")
	} else if e, ok := errors.AsType[*apiclient.Error](err); !ok || e.StatusCode != 401 {
		t.Fatal(err)
	}
	response, err = admin.Explain(t.Context(), request, true)
	if err != nil || !slices.ContainsFunc(response.Context, func(f api.DiagnosticField) bool { return f.Name == "mac" && f.Source == "request" }) {
		t.Fatal(response, err)
	}
	if _, err := admin.SetClientMember(t.Context(), "absent", mac, true); err == nil {
		t.Fatal("created undefined group")
	} else if e, ok := errors.AsType[*apiclient.Error](err); !ok || e.StatusCode != 404 {
		t.Fatal(err)
	}
	if _, err := guest.ClientImpact(t.Context(), "work", api.ClientImpactRequest{Joined: new(true)}, true); err == nil {
		t.Fatal("LAN guest read routing impact")
	} else if e, ok := errors.AsType[*apiclient.Error](err); !ok || e.StatusCode != 401 {
		t.Fatal(err)
	}
	impact, err := admin.ClientImpact(t.Context(), "work", api.ClientImpactRequest{Joined: new(true)}, true)
	if err != nil || len(impact.Rules) != 1 {
		t.Fatal(impact, err)
	}
	if _, err := admin.SetClientMember(t.Context(), "work", mac, false); err != nil {
		t.Fatal(err)
	}
	if len(c.settings.Members("work")) != 0 {
		t.Fatal("member not removed")
	}
}

func TestDiagnosticsAPIProtectsGlobalEvidence(t *testing.T) {
	c := diagnosticPlane(t, "domain(full: other-device.example) -> block\nclient(work) -> block", "")
	c.apiKey = "secret"
	ip := netip.MustParseAddr("203.0.113.77")
	c.core.domainRegistry.ObserveDNS([]domainObservation{{name: "other-device.example.", ips: []netip.Addr{ip}, bitmap: c.routingMatcher.domainMatcher.MatchDomainBitmap("other-device.example"), ttl: 120}}, time.Now())
	h := c.apiHandler("test", testClientIngress, nil)
	for _, query := range []struct{ path, body, evidence string }{
		{"/api/device/diagnostics/explain", `{"flow":{"destination":{"ip":"203.0.113.77","port":443}}}`, "other-device.example"},
		{"/api/device/diagnostics/explain", `{"kind":"domain","flow":{"destination":{"domain":"other-device.example"}}}`, "other-device.example"},
		{"/api/device/diagnostics/explain", `{"flow":{"destination":{"ip":"198.51.100.10","port":443}},"compare":{"bindings":[{"ip":"203.0.113.77","domains":["assumed.example"]}]}}`, "other-device.example"},
		{"/api/device/sets/work/impact", `{"joined":true,"flow":{"destination":{"ip":"203.0.113.77","port":443}}}`, "other-device.example"},
	} {
		w := apiTestRequest(h, "POST", query.path, query.body, "")
		if w.Code != 401 || strings.Contains(w.Body.String(), query.evidence) {
			t.Fatalf("LAN read global evidence: %d %s", w.Code, w.Body.String())
		}
		w = apiTestRequest(h, "POST", query.path, query.body, "secret")
		if w.Code != 200 || !strings.Contains(w.Body.String(), query.evidence) {
			t.Fatalf("administrator lost diagnostic evidence: %d %s", w.Code, w.Body.String())
		}
	}
}
