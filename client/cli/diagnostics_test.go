// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
)

func TestExplainCLIContextAndComparison(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/device/diagnostics/explain" || r.Method != "POST" || r.Header.Get("X-Dae-API") != "1" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var request api.ExplainRequest
		if err := json.UnmarshalRead(r.Body, &request); err != nil {
			t.Fatal(err)
		}
		if request.Context.MAC != "" || request.Context.SourcePort == nil || *request.Context.SourcePort != 40000 || request.Context.DSCP == nil || *request.Context.DSCP != 0 || request.Flow.SNI == nil || *request.Flow.SNI != "example.com" || !request.Compare.ClientSets["work"] {
			t.Fatalf("context lost: %+v", request)
		}
		_ = json.MarshalWrite(w, api.ExplainResponse{Schema: api.DiagnosticsSchemaVersion, Current: api.ExplainResult{Decision: api.ExplainDecision{Verdict: "kernel_direct", Complete: true, Outbound: "direct"}}})
	}))
	defer server.Close()
	command := NewExplainCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"route", "198.51.100.1:443", "--self", "--api", server.URL, "--source-port", "40000", "--dscp", "0", "--sni", "example.com", "--join", "work", "--json"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "kernel_direct") {
		t.Fatal(output.String())
	}
}

func TestClientCLIAdministratorMembership(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/api/clients/work/members/02:00:00:00:00:10" || r.Header.Get("X-Dae-API") != "1" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.MarshalWrite(w, api.ClientGroup{Name: "work", Members: []string{"02:00:00:00:00:10"}})
	}))
	defer server.Close()
	command := NewClientCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"join", "work", "--mac", "02:00:00:00:00:10", "--api", server.URL})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "02:00:00:00:00:10") {
		t.Fatal(output.String())
	}
}
