// SPDX-License-Identifier: AGPL-3.0-only

package domain_matcher

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestValidateSetAgreesWithBuild(t *testing.T) {
	for _, key := range []consts.RoutingDomainKey{consts.RoutingDomainKey_Full, consts.RoutingDomainKey_Suffix, consts.RoutingDomainKey_Keyword, consts.RoutingDomainKey_Regex} {
		for _, pattern := range []string{"", "example.com", "EXAMPLE.COM", "(", "a\x00b", "例子.test", ".example.com"} {
			matcher := NewAhocorasickSlimtrie(32)
			matcher.AddSet(0, []string{pattern}, key)
			built, checked := matcher.Build(), ValidateSet([]string{pattern}, key)
			if (built == nil) != (checked == nil) {
				t.Fatalf("%s(%q): build=%v validate=%v", key, pattern, built, checked)
			}
		}
	}
}
