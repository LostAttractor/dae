// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestStopInterruptsRequestsAndCloseJoins(t *testing.T) {
	for _, network := range []string{"tcp", "unix"} {
		for _, block := range []string{"context", "body"} {
			t.Run(network+"/"+block, func(t *testing.T) {
				address := "127.0.0.1:0"
				if network == "unix" {
					address = filepath.Join(t.TempDir(), "api.sock")
				}
				server, err := Listen(network, address)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(server.Close)
				started, interrupted, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
				finish := sync.OnceFunc(func() { close(release) })
				t.Cleanup(finish)
				server.SetHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(started)
					if block == "body" {
						_, _ = io.Copy(io.Discard, r.Body)
					} else {
						select {
						case <-r.Context().Done():
						case <-release:
							return
						}
					}
					close(interrupted)
					<-release // The owner must join even after cancellation.
				}))
				conn, err := net.Dial(network, server.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = conn.Close() })
				// Leave the body incomplete, including in the context-only case.
				if _, err := fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4096\r\n\r\nx"); err != nil {
					t.Fatal(err)
				}
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("request did not start")
				}
				stopped := make(chan struct{})
				go func() { server.Stop(); close(stopped) }()
				select {
				case <-stopped:
				case <-time.After(time.Second):
					t.Fatal("Stop waited for handler cleanup")
				}
				select {
				case <-interrupted:
				case <-time.After(time.Second):
					t.Fatal("Stop did not interrupt the request")
				}
				closed := make(chan struct{})
				go func() { server.Close(); close(closed) }()
				select {
				case <-closed:
					t.Fatal("Close returned while the handler still owned shared state")
				case <-time.After(20 * time.Millisecond):
				}
				finish()
				select {
				case <-closed:
				case <-time.After(time.Second):
					t.Fatal("Close did not finish after handler cleanup")
				}
			})
		}
	}
}
