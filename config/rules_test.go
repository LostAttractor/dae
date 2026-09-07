// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestRoutingControlsRequireRulesSection(t *testing.T) {
	for _, action := range []string{"must", "must_rules", "must_direct", "must_my_group", "direct(must)", "my_group(mark: 37, must)", "bump"} {
		for _, fallback := range []bool{false, true} {
			body := "dip(192.0.2.1) -> " + action + "\nfallback: direct"
			if fallback {
				body = "fallback: " + action
			}
			t.Run(body, func(t *testing.T) {
				sections, err := config_parser.Parse("global {}\nrouting {\n" + body + "\n}")
				if err != nil {
					t.Fatal(err)
				}
				_, err = New(sections)
				want := "rules { <filter> -> must }"
				if action == "bump" {
					want = "rules { <filter> -> bump }"
				}
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("expected migration instruction %q, got %v", want, err)
				}
			})
		}
	}
}
