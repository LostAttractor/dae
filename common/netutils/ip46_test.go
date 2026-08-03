/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"testing"
)

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
