// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func TestMITMUpstreamHalfClose(t *testing.T) {
	client, server := relayTestTCPPair(t)
	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = server.SetDeadline(time.Now().Add(time.Second))
	group := downloadTestGroup(t, t.Name(), func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	option := &DialOption{Direct: true, Dialer: group.Dialers[0], Outbound: group, NetworkType: *common.NetworkTCP4.NetworkType()}
	upstream := &mitmUpstreamConn{Conn: client, httpUpstream: newHTTPUpstream(option, client)}
	defer upstream.Close()
	lease := upstream.DependencyLease()
	if err := upstream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(server)
	if err != nil || len(body) != 0 {
		t.Fatalf("write EOF=%q err=%v", body, err)
	}
	if !lease.Valid() {
		t.Fatal("half-close retired resource")
	}
	done := make(chan error, 1)
	go func() { _, err := io.WriteString(server, "tail"); done <- errors.Join(err, server.CloseWrite()) }()
	body, err = io.ReadAll(upstream)
	if err != nil || string(body) != "tail" {
		t.Fatalf("remaining read=%q err=%v", body, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !lease.Valid() {
		t.Fatal("read EOF retired resource before Close")
	}
}

func TestMITMUpstreamHalfCloseUnsupported(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := &mitmUpstreamConn{Conn: client}
	if err := netproxy.CloseWrite(conn); err != errors.ErrUnsupported {
		t.Fatalf("unsupported half-close=%v", err)
	}
}
