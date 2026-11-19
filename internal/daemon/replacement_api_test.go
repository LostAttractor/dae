// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/api/client"
	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/internal/apiserver"
	"github.com/daeuniverse/dae/internal/testutil"
)

func TestExecutableOperationAuthenticationAndOwnership(t *testing.T) {
	o := newOperations()
	path := filepath.Join(t.TempDir(), "dae.sock")
	server, err := apiserver.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.SetLocalServices(apiserver.LocalServices{Operations: o})
	remote, err := client.New(client.Options{Endpoint: "unix://" + path})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	for _, request := range []api.OperationRequest{
		{Kind: "reload", Replace: true},
		{Kind: "reload", ExecutablePID: os.Getpid() + 1},
		{Kind: "suspend", ExecutablePID: os.Getpid()},
		{Kind: "reload", ExecutableFD: 3},
		{Kind: "reload", ExecutablePID: os.Getpid(), ExecutableFD: -1},
	} {
		if _, err := remote.SubmitOperation(t.Context(), request); err == nil {
			t.Fatalf("accepted invalid request: %+v", request)
		}
	}
	for _, complete := range []bool{false, true} {
		status, err := remote.SubmitOperation(t.Context(), api.OperationRequest{Kind: "reload", ExecutablePID: os.Getpid(), Replace: true})
		if err != nil {
			t.Fatal(err)
		}
		file := o.records[status.ID].executable
		if replace, err := needsReplacement(file, false); replace || err != nil {
			t.Fatalf("wrong peer executable: %v, %v", replace, err)
		}
		<-o.requests
		if complete {
			o.start(status.ID)
			o.finish(status.ID, "ok", nil)
		} else {
			o.stop()
			o.mu.Lock()
			o.closed = false
			o.mu.Unlock()
		}
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("FD not closed on completion/cancel: %v", err)
		}
	}
	path = filepath.Join(t.TempDir(), "candidate")
	const candidateContents = elf.ELFMAG + "candidate"
	if err := os.WriteFile(path, []byte(candidateContents), 0700); err != nil {
		t.Fatal(err)
	}
	candidate, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Close()
	request := api.OperationRequest{Kind: "reload", ExecutablePID: os.Getpid(), ExecutableFD: int(candidate.Fd())}
	// The submitted descriptor still identifies the chosen inode after the path changes.
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0600); err != nil {
		t.Fatal(err)
	}
	status, err := remote.SubmitOperation(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Close()
	<-o.requests
	record := o.records[status.ID]
	if contents, err := io.ReadAll(record.executable); err != nil || string(contents) != candidateContents {
		t.Fatalf("wrong candidate: %q, %v", contents, err)
	}
	if request, ok := o.start(status.ID); !ok || !request.Replace {
		t.Fatalf("explicit descriptor must force replacement: %+v", request)
	}
	o.finish(status.ID, "ok", nil)
	invalid, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer invalid.Close()
	request.ExecutableFD = int(invalid.Fd())
	if _, err := remote.SubmitOperation(t.Context(), request); err == nil {
		t.Fatal("accepted non-executable candidate")
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.SubmitOperation(t.Context(), request); err == nil {
		t.Fatal("accepted interpreter script as replacement executable")
	}
	if err := o.beginReplacement(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.SubmitOperation(api.OperationRequest{Kind: "reload"}); !errors.Is(err, api.ErrOperationsBusy) {
		t.Fatal(err)
	}
	o.endReplacement()
	if _, err := o.SubmitOperation(api.OperationRequest{Kind: "reload"}); err != nil {
		t.Fatal(err)
	}
	if err := o.beginReplacement(); !errors.Is(err, api.ErrOperationsBusy) {
		t.Fatalf("discarded queued operations: %v", err)
	}

	tcp := httptest.NewTLSServer(apiserver.NewHandler(apiserver.Options{AdminKey: "key", Operations: o}))
	defer tcp.Close()
	remoteTCP, err := client.New(client.Options{Endpoint: tcp.URL, RootCAs: testutil.TLSRoots(tcp), APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}
	defer remoteTCP.Close()
	for _, request := range []api.OperationRequest{
		{Kind: "reload", Replace: true, ExecutablePID: os.Getpid()},
		request,
	} {
		_, err := remoteTCP.SubmitOperation(t.Context(), request)
		response, ok := errors.AsType[*client.Error](err)
		if !ok || response.StatusCode != http.StatusForbidden {
			t.Fatalf("remote replacement accepted: %v", err)
		}
	}
}

func TestReplacementPreservesAPISocketIdentity(t *testing.T) {
	manager, err := network.NewInterfaceManager()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	for _, lan := range []bool{false, true} {
		t.Run(fmt.Sprint("lan=", lan), func(t *testing.T) {
			port := freeLocalPort(t)
			policy := localAPIConfig(port)
			if lan {
				policy = config.API{Listen: fmt.Sprint(port)}
			}
			patterns := []string{"lo"}
			server, update, err := prepareAPIServer(nil, policy, patterns, manager, false)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			update.Commit()
			state := &replacementState{manifest: replacementManifest{ManagementBinding: server.Binding()}, files: make(map[string]*os.File)}
			defer state.close()
			get := func(s *apiserver.Server) (string, *os.File) {
				t.Helper()
				if lan {
					data, err := s.InterfaceFiles()
					if err != nil || len(data) != 1 {
						t.Fatalf("exported LAN sockets: %v, %v", data, err)
					}
					for index, file := range data {
						return fmt.Sprintf("management/%d", index), file
					}
				}
				file, err := s.File()
				if err != nil {
					t.Fatal(err)
				}
				return "management", file
			}
			name, file := get(server)
			old, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			state.files[name] = file
			next, err := state.takeManagement(policy, patterns)
			if err != nil || next == nil {
				t.Fatalf("restore: %v", err)
			}
			defer next.Close()
			server.Close()
			current, update, err := prepareAPIServer(next, policy, patterns, manager, true)
			if err != nil || current != next {
				t.Fatalf("inherited listener was not reused: %v", err)
			}
			update.Commit()
			next.Activate()
			name2, file := get(next)
			defer file.Close()
			info, err := file.Stat()
			if err != nil || name2 != name || !os.SameFile(old, info) {
				t.Fatalf("API socket changed across handoff: %v", err)
			}
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
		})
	}
}
