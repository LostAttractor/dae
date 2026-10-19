// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/dnscache"
	dns "github.com/miekg/dns"
)

func TestResolverCachePendingDialDeadlineChanges(t *testing.T) {
	for _, mode := range []string{"past", "shorten", "extend", "clear"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started, release := make(chan struct{}), make(chan struct{})
				dial := cacheDNSDial(dnscache.New(1, 4096), func(ctx context.Context, _, _ string) (net.Conn, error) {
					close(started)
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-release:
						return &cacheWireConn{makeReply: func(*dns.Msg) []byte { return nil }}, nil
					}
				})
				conn, err := dial(t.Context(), "udp", "192.0.2.53:53")
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if mode != "past" {
					_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
				}
				wire, _ := new(dns.Msg).SetQuestion("deadline.test.", dns.TypeA).Pack()
				done := make(chan error, 1)
				go func() { _, err := conn.Write(wire); done <- err }()
				<-started
				switch mode {
				case "past":
					_ = conn.SetWriteDeadline(time.Now().Add(-time.Second))
				case "shorten":
					_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
					time.Sleep(100 * time.Millisecond)
				case "extend":
					_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
					time.Sleep(2 * time.Second)
				case "clear":
					_ = conn.SetWriteDeadline(time.Time{})
					time.Sleep(2 * time.Second)
				}
				synctest.Wait()
				if mode == "past" || mode == "shorten" {
					select {
					case err := <-done:
						if !errors.Is(err, os.ErrDeadlineExceeded) {
							t.Fatalf("expired write returned %v", err)
						}
					default:
						t.Fatal("write remained blocked after its deadline")
					}
				} else {
					select {
					case err := <-done:
						t.Fatalf("obsolete deadline ended the dial: %v", err)
					default:
					}
					close(release)
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					// The dial timer must no longer affect an established connection.
					_ = conn.SetWriteDeadline(time.Time{})
					time.Sleep(20 * time.Second)
					if _, err := conn.Write(wire); err != nil {
						t.Fatal(err)
					}
				}
			})
		})
	}
}

func TestResolverCacheRetriesDialAfterDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		dial := cacheDNSDial(dnscache.New(1, 4096), func(ctx context.Context, _, _ string) (net.Conn, error) {
			calls++
			if calls == 1 {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return &cacheWireConn{makeReply: func(*dns.Msg) []byte { return nil }}, nil
		})
		conn, err := dial(t.Context(), "udp", "192.0.2.53:53")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		wire, _ := new(dns.Msg).SetQuestion("deadline.test.", dns.TypeA).Pack()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write(wire); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("first write: %v", err)
		}
		_ = conn.SetDeadline(time.Time{})
		if _, err := conn.Write(wire); err != nil || calls != 2 {
			t.Fatalf("retry: calls=%d, err=%v", calls, err)
		}
	})
}
