/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package consts

import "testing"

func TestVerifyRerouteMode(t *testing.T) {
	for _, mode := range []string{"none", "while_needed", "force"} {
		if err := VerifyRerouteMode(mode); err != nil {
			t.Errorf("VerifyRerouteMode(%q) = %v", mode, err)
		}
	}
	for _, mode := range []string{"", "NONE", "whileneeded", "always", "force "} {
		if err := VerifyRerouteMode(mode); err == nil {
			t.Errorf("VerifyRerouteMode(%q) unexpectedly succeeded", mode)
		}
	}
}

func TestVerifySniffVerifyMode(t *testing.T) {
	for _, mode := range []string{"none", "loose", "strict"} {
		if err := VerifySniffVerifyMode(mode); err != nil {
			t.Errorf("VerifySniffVerifyMode(%q) = %v", mode, err)
		}
	}
	for _, mode := range []string{"", "NONE", "lose", "strict ", "verify"} {
		if err := VerifySniffVerifyMode(mode); err == nil {
			t.Errorf("VerifySniffVerifyMode(%q) unexpectedly succeeded", mode)
		}
	}
}
