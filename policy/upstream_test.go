/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"
)

func TestUpstreamResolverWaitHonorsContext(t *testing.T) {
	resolver := &UpstreamResolver{}
	resolver.mu.Lock()
	resolver.resolving = make(chan struct{})
	resolver.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := resolver.GetUpstream(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GetUpstream error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("GetUpstream ignored context for %s", elapsed)
	}
}

func TestUpstreamResolverCallbacks(t *testing.T) {
	raw, err := url.Parse("udp://192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("nil", func(t *testing.T) {
		resolver := &UpstreamResolver{Raw: raw}
		if _, err := resolver.GetUpstream(context.Background()); err != nil {
			t.Fatalf("GetUpstream: %v", err)
		}
	})

	t.Run("called once", func(t *testing.T) {
		calls := 0
		resolver := &UpstreamResolver{
			Raw: raw,
			FinishInitCallback: func(upstream *Upstream) {
				calls++
				if upstream.Hostname != "192.0.2.1" {
					t.Errorf("callback hostname = %q, want 192.0.2.1", upstream.Hostname)
				}
			},
		}
		for i := 0; i < 2; i++ {
			if _, err := resolver.GetUpstream(context.Background()); err != nil {
				t.Fatalf("GetUpstream: %v", err)
			}
		}
		if calls != 1 {
			t.Fatalf("callback calls = %d, want 1", calls)
		}
	})
}
