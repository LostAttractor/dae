// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/daeuniverse/dae/api"
	apiclient "github.com/daeuniverse/dae/api/client"
)

func TestDiagnosticsAPIAndClientAdministration(t *testing.T) {
	c := diagnosticPlane(t, "client(work) -> block", "")
	c.apiKey = "secret"
	server := httptest.NewServer(c.apiHandler("test", testClientMAC, nil))
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
	response, err = guest.Explain(t.Context(), request, true)
	if err != nil || !slices.ContainsFunc(response.Context, func(f api.DiagnosticField) bool { return f.Name == "mac" && f.Source == "request" }) {
		t.Fatal(response, err)
	}
	if _, err := admin.SetClientMember(t.Context(), "absent", mac, true); err == nil {
		t.Fatal("created undefined group")
	} else if e, ok := errors.AsType[*apiclient.Error](err); !ok || e.StatusCode != 404 {
		t.Fatal(err)
	}
	impact, err := guest.ClientImpact(t.Context(), "work", api.ClientImpactRequest{Joined: new(true)}, true)
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
