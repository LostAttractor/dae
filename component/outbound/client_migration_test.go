/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"encoding/base64"
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
)

// Use the DAE node parser and path builder, including this package's production
// registration imports. Constructing these static clients must not dial a peer.
func TestClientLinksBuild(t *testing.T) {
	encode := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	cases := []struct{ name, link string }{
		{"VMess", "vmess://" + encode(`{"v":"2","ps":"client","add":"127.0.0.1","port":"9","id":"01234567-89ab-cdef-0123-456789abcdef","aid":"0","net":"tcp","type":"none","tls":""}`)},
		{"VLESS", "vless://01234567-89ab-cdef-0123-456789abcdef@127.0.0.1:9?encryption=none&type=tcp&security=none#client"},
		{"SSR", "ssr://" + encode("127.0.0.1:9:origin:aes-128-cfb:plain:cGFzc3dvcmQ/?remarks=Y2xpZW50")},
		{"SS stream", "ss://" + encode("aes-128-cfb:password") + "@127.0.0.1:9#client"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, err := NewDialerSet([]NodeDescriptor{{Link: tc.link, Required: true}})
			if err != nil {
				t.Fatal(err)
			}
			if len(set.nodeInfos) != 1 {
				t.Fatalf("parsed %d nodes, want one", len(set.nodeInfos))
			}
			client, err := set.BuildPath(NodePath(set.nodeInfos[0]), &dialer.GlobalOption{}, t.Name())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
