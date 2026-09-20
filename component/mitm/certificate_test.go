// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestCertificateSelectionIsLocal(t *testing.T) {
	for _, preserve := range []bool{true, false} {
		authority, roots := http3TestAuthority(t)
		p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com"), PreserveRoute: preserve}}}}
		h := testHost(t, Options{Authority: authority}, Instance{Plugin: p})
		left, right := net.Pipe()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		server := tls.Server(left, h.interceptionTLSConfig(plugin.Flow{Host: "example.com", Port: 443}))
		client := tls.Client(right, &tls.Config{RootCAs: roots, ServerName: "example.com"})
		done := make(chan error, 1)
		go func() { done <- server.HandshakeContext(ctx) }()
		clientErr, serverErr := client.HandshakeContext(ctx), <-done
		cancel()
		left.Close()
		right.Close()
		if clientErr != nil || serverErr != nil {
			t.Fatalf("local handshake: client=%v server=%v", clientErr, serverErr)
		}
		leaf := client.ConnectionState().PeerCertificates[0]
		if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
			t.Fatalf("unexpected local identity: %v", leaf.DNSNames)
		}
	}
}
