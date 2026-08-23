/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import "testing"

func TestParsePositivePID(t *testing.T) {
	for _, raw := range []string{"", "dae", "0", "-1", "-42", "2147483648", "4294967295", "4294967296"} {
		if _, err := parsePositivePID(raw); err == nil {
			t.Errorf("parsePositivePID(%q) unexpectedly succeeded", raw)
		}
	}
	if pid, err := parsePositivePID("123"); err != nil || pid != 123 {
		t.Fatalf("parsePositivePID(123) = %d, %v", pid, err)
	}
}
