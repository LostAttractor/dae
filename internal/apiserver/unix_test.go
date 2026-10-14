// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixAdminListenerChecksQueuedPeer(t *testing.T) {
	for _, sameUID := range []bool{true, false} {
		t.Run(map[bool]string{true: "owner", false: "other UID"}[sameUID], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "admin.sock")
			listener, err := bindUnix(path)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			// Queue the connection while the socket is world-writable, then
			// chmod it just as listenUnix does before starting the HTTP server.
			if err := os.Chmod(path, 0777); err != nil {
				t.Fatal(err)
			}
			client, err := net.Dial("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Geteuid())
			if !sameUID {
				// Change the permitted UID, not the process's credentials, so
				// this exercises real SO_PEERCRED without requiring root.
				uid++
			}
			guard := &unixAdminListener{Listener: listener, uid: uid}
			accepted := make(chan error, 1)
			go func() {
				conn, err := guard.Accept()
				if conn != nil {
					_, err = conn.Write([]byte("authorized"))
					_ = conn.Close()
				}
				accepted <- err
			}()
			_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
			buffer := make([]byte, 32)
			n, readErr := client.Read(buffer)
			_ = guard.Close()
			acceptErr := <-accepted
			if sameUID {
				if readErr != nil || string(buffer[:n]) != "authorized" || acceptErr != nil {
					t.Fatalf("owner refused: %q %v %v", buffer[:n], readErr, acceptErr)
				}
			} else {
				if n != 0 || readErr == nil || !errors.Is(acceptErr, net.ErrClosed) {
					t.Fatalf("unauthorized connection accepted: %q %v %v", buffer[:n], readErr, acceptErr)
				}
				if err, ok := readErr.(net.Error); ok && err.Timeout() {
					t.Fatal("unauthorized connection was left open")
				}
			}
		})
	}
}
