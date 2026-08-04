/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package consts

import "testing"

func TestVerifyRerouteMode(t *testing.T) {
	for _, mode := range []string{"none", "while_needed", "force"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("VerifyRerouteMode(%q) should not panic: %v", mode, r)
				}
			}()
			VerifyRerouteMode(mode)
		}()
	}
	for _, mode := range []string{"", "NONE", "whileneeded", "always", "force "} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("VerifyRerouteMode(%q) should panic", mode)
				}
			}()
			VerifyRerouteMode(mode)
		}()
	}
}

func TestVerifySniffVerifyMode(t *testing.T) {
	for _, mode := range []string{"none", "loose", "strict"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("VerifySniffVerifyMode(%q) should not panic: %v", mode, r)
				}
			}()
			VerifySniffVerifyMode(mode)
		}()
	}
	for _, mode := range []string{"", "NONE", "lose", "strict ", "verify"} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("VerifySniffVerifyMode(%q) should panic", mode)
				}
			}()
			VerifySniffVerifyMode(mode)
		}()
	}
}
