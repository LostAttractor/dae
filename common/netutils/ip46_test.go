/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	outboundcommon "github.com/daeuniverse/outbound/common"
)

func TestOutboundResolverUsesDefaultResolver(t *testing.T) {
	original := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = original })

	var dialed atomic.Bool
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dialed.Store(true)
			return nil, errors.New("resolver dial intercepted")
		},
	}
	if _, err := outboundcommon.ResolveUDPAddr("default-resolver-integration.invalid:53"); err == nil {
		t.Fatal("outbound resolver unexpectedly succeeded")
	}
	if !dialed.Load() {
		t.Fatal("outbound resolver did not use net.DefaultResolver")
	}
}

func TestResolveIp46ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ResolveIp46Context(ctx, "context-cancellation.invalid"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveIp46Context returned %v, want context cancellation", err)
	}
}

func TestResolveIp46(t *testing.T) {
	ip46, err := ResolveIp46("ipv6.google.com")
	if err != nil {
		t.Fatal(err)
	}
	if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
		t.Fatal("No record")
	}
	t.Log(ip46)
}
