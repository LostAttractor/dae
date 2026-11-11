// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/api/client"
)

func TestInheritedSocketOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dae.sock")
	old, err := Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	file, err := old.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	candidate, err := FromFile(file, "unix")
	if err != nil {
		t.Fatal(err)
	}
	candidate.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("rejected candidate removed socket: %v", err)
	}
	next, err := FromFile(file, "unix")
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	old.SetOwnership(false)
	old.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("predecessor removed socket: %v", err)
	}
	next.SetOwnership(true)
	next.SetHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"same","kind":"reload","state":"completed"}`))
	}))
	next.Activate()
	remote, err := client.New(client.Options{Endpoint: "unix://" + path})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	status, err := remote.Operation(t.Context(), "same")
	if err != nil || status.ID != "same" {
		t.Fatalf("new listener cannot serve: %+v, %v", status, err)
	}
	next.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("successor did not unlink socket: %v", err)
	}
}
