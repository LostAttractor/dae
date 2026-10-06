// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	outboundsmux "github.com/daeuniverse/outbound/transport/smux"
	"github.com/xtaci/smux"
)

func relaySmuxOutbound(t *testing.T) (*outboundsmux.Smux, net.Conn, *smux.Stream) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	headerRead := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(server, make([]byte, 2))
		headerRead <- err
	}()
	outbound := &outboundsmux.Smux{Dialer: tcpTestDialer{conn: client}, MaxConnections: 1}
	t.Cleanup(func() { _ = outbound.Close() })
	if err := outbound.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-headerRead; err != nil {
		t.Fatal(err)
	}
	config := smux.DefaultConfig()
	config.KeepAliveDisabled = true
	session, err := smux.Server(server, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	conn, err := outbound.DialContext(t.Context(), "tcp", "target.example:443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	peer, err := session.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	return outbound, conn, peer
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
