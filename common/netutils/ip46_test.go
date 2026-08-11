/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"errors"
	"testing"
)

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
