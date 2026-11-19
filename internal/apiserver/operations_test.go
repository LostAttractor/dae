// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
	"golang.org/x/sys/unix"
)

func TestLocalReloadLogHeaderValidation(t *testing.T) {
	pid, uid := os.Getpid(), uint32(os.Geteuid())
	for _, test := range []struct {
		name, kind string
		local      bool
		pid        int
		uid        uint32
		header     []string
		want       int
	}{
		{"TCP", "reload", false, pid, uid, []string{"3"}, http.StatusForbidden},
		{"different UID", "reload", true, pid, uid + 1, []string{"3"}, http.StatusForbidden},
		{"different PID", "reload", true, pid + 1, uid, []string{"3"}, http.StatusForbidden},
		{"no PID", "reload", true, 0, uid, []string{"3"}, http.StatusForbidden},
		{"suspend", "suspend", true, pid, uid, []string{"3"}, http.StatusForbidden},
		{"empty", "reload", true, pid, uid, []string{""}, http.StatusBadRequest},
		{"negative", "reload", true, pid, uid, []string{"-1"}, http.StatusBadRequest},
		{"stdio", "reload", true, pid, uid, []string{"2"}, http.StatusBadRequest},
		{"not decimal", "reload", true, pid, uid, []string{"0x7"}, http.StatusBadRequest},
		{"duplicate headers", "reload", true, pid, uid, []string{"3", "4"}, http.StatusBadRequest},
		{"comma separated", "reload", true, pid, uid, []string{"3, 4"}, http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &resourceStoreTest{}
			handler := NewHandler(Options{AdminKey: "secret", Operations: store})
			var addr net.Addr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
			if test.local {
				addr = &net.UnixAddr{Net: "unix", Name: "dae.sock"}
			}
			ctx := context.WithValue(t.Context(), http.LocalAddrContextKey, addr)
			ctx = context.WithValue(ctx, peerCredentialsKey{}, &unix.Ucred{Pid: int32(pid), Uid: test.uid})
			body := fmt.Sprintf(`{"kind":%q,"executable_pid":%d}`, test.kind, test.pid)
			req := httptest.NewRequestWithContext(ctx, "POST", "https://localhost/api/operations", strings.NewReader(body))
			req.Header.Set("X-Dae-API", "1")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer secret")
			for _, value := range test.header {
				req.Header.Add(api.ReloadLogFDHeader, value)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != test.want || store.calls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", recorder.Code, store.calls, recorder.Body)
			}
		})
	}
}
