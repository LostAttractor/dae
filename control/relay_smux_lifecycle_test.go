// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux/smuxtest"
)

func relaySmuxOutbound(t testing.TB) (*singmux.Mux, net.Conn, *smuxtest.Stream) {
	t.Helper()
	outbound, server := smuxTestOutbound(t)
	session := smuxtest.Server(server)
	t.Cleanup(func() { _ = session.Close() })
	conn, err := outbound.DialContext(t.Context(), "tcp", "target.example:443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	peer, err := session.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	return outbound, conn, peer
}

// smuxTestOutbound connects an smux client over a pipe and returns the far
// end after the sing-mux header, for smuxtest.Server to serve.
func smuxTestOutbound(t testing.TB) (*singmux.Mux, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	headerRead := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(server, make([]byte, 2))
		headerRead <- err
	}()
	outbound := &singmux.Mux{Dialer: tcpTestDialer{conn: client}, MaxConnections: 1}
	t.Cleanup(func() { _ = outbound.Close() })
	// Before Close, which would otherwise write what an unread carrier holds.
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	if err := outbound.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-headerRead; err != nil {
		t.Fatal(err)
	}
	return outbound, server
}

func TestRelaySmuxConnectionOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		origin netproxy.FailureOrigin
	}{
		{"drain expiry", ""},
		{"caller reset", netproxy.OriginCaller},
		{"target rejection", netproxy.OriginTarget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outbound, right, peer := relaySmuxOutbound(t)
			left, client := relayTestTCPPair(t)
			done := startTCPRelayTest(t, left, right, 50*time.Millisecond)
			switch tc.name {
			case "drain expiry":
				// The peer stays open until the relay's EOF drain expires.
				if err := client.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			case "caller reset":
				if err := client.SetLinger(0); err != nil {
					t.Fatal(err)
				}
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			case "target rejection":
				if _, err := peer.Write([]byte("\x01connection refused")); err != nil {
					t.Fatal(err)
				}
				if err := peer.Close(); err != nil {
					t.Fatal(err)
				}
			}
			err := waitTCPRelayTest(t, done)
			if tc.origin == "" {
				if err != nil {
					t.Fatalf("local drain was reported as a failure: %v", err)
				}
			} else {
				failures := netproxy.Failures(err)
				if len(failures) != 1 || failures[0].Origin != tc.origin {
					t.Fatalf("relay lost provenance or added a cleanup failure: %+v", failures)
				}
			}
			if state := outbound.Snapshot(); !state.Accepting || state.EpisodeID != 0 || state.RecoveryRequired {
				t.Fatalf("connection outcome disturbed the session: %+v", state)
			}
		})
	}
}
