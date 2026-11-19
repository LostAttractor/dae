// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"bytes"
	"encoding/json/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/internal/testutil"
)

func TestReloadCommandsUseConfiguredAPI(t *testing.T) {
	for _, kind := range []string{"reload", "suspend"} {
		for _, explicit := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/environment", true: "/flag"}[explicit], func(t *testing.T) {
				t.Setenv("DAE_API_KEY", "command-test-key")
				requests := 0
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests++
					if r.Header.Get("Authorization") != "Bearer command-test-key" {
						t.Error("missing configured API credential")
					}
					switch r.Method + " " + r.URL.Path {
					case "POST /api/operations":
						var request api.OperationRequest
						if err := json.UnmarshalRead(r.Body, &request); err != nil {
							t.Error(err)
						}
						if request.Kind != kind || !request.Abort || request.ExecutablePID != 0 || request.ExecutableFD != 0 {
							t.Errorf("operation request = %+v", request)
						}
						w.WriteHeader(http.StatusAccepted)
						_ = json.MarshalWrite(w, api.Operation{ID: "mine", Kind: kind, State: "queued"})
					case "GET /api/operations/mine":
						_ = json.MarshalWrite(w, api.Operation{ID: "mine", Kind: kind, State: "completed", Result: "finished"})
					default:
						t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer server.Close()
				t.Setenv("DAE_API_CA", testutil.TLSFile(t, server))
				t.Setenv("DAE_API_ENDPOINT", server.URL)
				args := []string{"--abort"}
				if explicit {
					t.Setenv("DAE_API_ENDPOINT", "unix:///unused/dae.sock")
					args = append(args, "--api", server.URL)
				}
				command := newReloadCommand(kind == "suspend")
				var output bytes.Buffer
				command.SetOut(&output)
				command.SetErr(&output)
				command.SetArgs(args)
				if err := command.ExecuteContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				if requests != 2 || !strings.Contains(output.String(), "finished") {
					t.Fatalf("requests=%d, output=%q", requests, output.String())
				}
			})
		}
	}
}

func TestBinaryReloadElevatesBeforeOpeningCandidate(t *testing.T) {
	const child = "DAE_TEST_RELOAD_ELEVATION"
	const relative = "current/../release/dae"
	if os.Getenv(child) == "1" {
		command := newReloadCommand(false)
		command.SetArgs([]string{"--abort", "--binary", relative})
		t.Fatal(command.ExecuteContext(t.Context())) // The helper exits the CLI.
	}
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged caller")
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "dae.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "sudo")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(helper, 0755); err != nil {
		t.Fatal(err)
	}
	endpoint := "unix://" + socket
	t.Setenv(child, "1")
	t.Setenv("PATH", dir)
	t.Setenv("DAE_API_ENDPOINT", endpoint)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), self, "-test.run=^TestBinaryReloadElevatesBeforeOpeningCandidate$")
	command.Dir = dir
	output, err := command.CombinedOutput()
	want := self + "\nreload\n--abort=true\n--api=" + endpoint + "\n--binary=" + dir + "/" + relative + "\n"
	if err != nil || !strings.HasSuffix(string(output), want) {
		t.Fatalf("elevation args = %q, %v; want suffix %q", output, err, want)
	}
}
