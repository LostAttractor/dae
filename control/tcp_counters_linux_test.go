// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestTCPWriteCounter(t *testing.T) {
	for _, reset := range []bool{false, true} {
		name := "drain"
		if reset {
			name = "reset_with_pending_write"
		}
		t.Run(name, func(t *testing.T) {
			conn, peer := relayTestTCPPair(t)
			if err := conn.SetWriteBuffer(32 << 10); err != nil {
				t.Fatal(err)
			}
			counter, err := tcpWriteCounter(conn)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := counter(); err != nil || n != 0 {
				t.Fatalf("handshake counted as payload: %d, %v", n, err)
			}
			type result struct {
				n   int
				err error
			}
			done := make(chan result, 1)
			payload := bytes.Repeat([]byte("payload"), 1<<20)
			go func() {
				n, err := conn.Write(payload)
				done <- result{n, err}
			}()
			var high uint64
			// Observe queued data before allowing the receiver to proceed.
			for deadline := time.Now().Add(time.Second); high == 0; {
				n, err := counter()
				if err != nil {
					t.Fatal(err)
				}
				high = max(high, n)
				if time.Now().After(deadline) {
					t.Fatal("pending write was not observed")
				}
			}
			received := make(chan error, 1)
			if reset {
				if err := peer.SetLinger(0); err != nil {
					t.Fatal(err)
				}
				_ = peer.Close()
			} else {
				go func() {
					_, err := io.CopyN(io.Discard, peer, int64(len(payload)))
					received <- err
				}()
			}
			for {
				select {
				case result := <-done:
					if !reset && (result.err != nil || result.n != len(payload)) {
						t.Fatalf("write: %+v", result)
					}
					if reset && result.err == nil {
						t.Fatal("reset did not interrupt blocked write")
					}
					if high > uint64(result.n) {
						t.Fatalf("sample %d exceeds actual write %d (%v)", high, result.n, result.err)
					}
					if !reset {
						if err := <-received; err != nil {
							t.Fatal(err)
						}
						n, err := counter()
						if err != nil || n != uint64(result.n) {
							t.Fatalf("final sample %d, %v; want %d", n, err, result.n)
						}
					}
					_ = conn.Close()
					if _, err := counter(); !errors.Is(err, net.ErrClosed) {
						t.Fatalf("closed descriptor still sampled: %v", err)
					}
					return
				default:
					n, err := counter()
					if err == nil {
						high = max(high, n)
					}
				}
			}
		})
	}
}
