//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"net"
	"strings"
	"testing"
)

func TestInstallDefaultResolverUnsupported(t *testing.T) {
	original := net.DefaultResolver
	err := InstallDefaultResolver(0)
	if err == nil || !strings.Contains(err.Error(), "requires Linux SO_MARK support") {
		t.Fatalf("InstallDefaultResolver returned %v, want unsupported error", err)
	}
	if net.DefaultResolver != original || defaultResolverState.configured {
		t.Fatal("unsupported resolver installation changed global state")
	}
}
