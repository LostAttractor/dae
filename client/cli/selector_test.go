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

func TestSelectorCLIListsSelectsAndResets(t *testing.T) {
	t.Setenv("DAE_API_KEY", "selector-secret")
	state := api.SelectorState{Name: "proxy/香港", NodeID: "one", DefaultNodeID: "one", Nodes: []api.SelectorNode{
		{ID: "one", Name: "First"}, {ID: "two", Name: "香港 01"},
		{ID: "duplicate-a", Name: "Duplicate"}, {ID: "duplicate-b", Name: "Duplicate"},
	}}
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer selector-secret" {
			t.Error("missing configured credentials")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" && r.URL.Path == "/api/selectors" {
			_ = json.MarshalWrite(w, api.SelectorsResponse{Selectors: []api.SelectorState{state}, AdminEnabled: true})
			return
		}
		if r.URL.EscapedPath() != "/api/selectors/proxy%2F%E9%A6%99%E6%B8%AF" || r.Header.Get("X-Dae-API") != "1" {
			t.Errorf("wrong selector mutation: %s %s", r.Method, r.URL.EscapedPath())
		}
		switch r.Method {
		case "PUT":
			var request api.SelectNodeRequest
			if err := json.UnmarshalRead(r.Body, &request); err != nil {
				t.Error(err)
			}
			state.NodeID, state.Overridden = request.NodeID, true
		case "DELETE":
			state.NodeID, state.Overridden = state.DefaultNodeID, false
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
		writes++
		_ = json.MarshalWrite(w, state)
	}))
	defer server.Close()
	t.Setenv("DAE_API_ENDPOINT", server.URL)
	run := func(args ...string) (string, error) {
		cmd := NewSelectorCommand()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SetArgs(args)
		err := cmd.ExecuteContext(t.Context())
		return output.String(), err
	}
	for _, args := range [][]string{nil, {"proxy/香港"}, {"--json"}} {
		if text, err := run(args...); err != nil || !strings.Contains(text, "香港 01") {
			t.Fatalf("list %v: %s, %v", args, text, err)
		}
	}
	if _, err := run("set", "proxy/香港", "香港 01"); err != nil || state.NodeID != "two" || writes != 1 {
		t.Fatalf("name selection failed: %+v %v", state, err)
	}
	for _, args := range [][]string{{"set", "proxy/香港", "Duplicate"}, {"set", "proxy/香港", "unknown"}, {"set", "missing", "one"}, {"set", "proxy/香港"}} {
		if _, err := run(args...); err == nil || writes != 1 {
			t.Fatalf("invalid selection %v reached mutation API: %v", args, err)
		}
	}
	text, err := run("set", "proxy/香港", "duplicate-b", "--json")
	var selected api.SelectorState
	if err != nil || json.Unmarshal([]byte(text), &selected) != nil || selected.NodeID != "duplicate-b" || writes != 2 {
		t.Fatalf("ID selection: %s %v", text, err)
	}
	if _, err := run("reset", "proxy/香港"); err != nil || state.NodeID != "one" || state.Overridden || writes != 3 {
		t.Fatalf("reset failed: %+v %v", state, err)
	}
}

func TestSelectorCLISavedFallbackAndAPIFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "GET" {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"selector has no configured default"}`))
			return
		}
		_ = json.MarshalWrite(w, api.SelectorsResponse{Selectors: []api.SelectorState{{Name: "proxy", NodeID: "one", Overridden: true,
			SavedSelection: &api.SavedSelectorSelection{Name: "Saved HK", Status: "missing"}, Nodes: []api.SelectorNode{{ID: "one", Name: "Temporary"}},
		}}})
	}))
	defer server.Close()
	cmd := NewSelectorCommand()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--api", server.URL, "proxy"})
	if err := cmd.ExecuteContext(t.Context()); err != nil || !strings.Contains(output.String(), "Saved HK (missing)") || !strings.Contains(output.String(), "temporarily") {
		t.Fatal(output.String(), err)
	}
	cmd = NewSelectorCommand()
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"--api", server.URL, "reset", "proxy"})
	if err := cmd.ExecuteContext(t.Context()); err == nil || !strings.Contains(err.Error(), "no configured default") {
		t.Fatalf("API rejection was hidden: %v", err)
	}
}
