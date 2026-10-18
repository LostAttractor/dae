// SPDX-License-Identifier: AGPL-3.0-only

package domain_matcher

import (
	"fmt"
	"regexp"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/v2rayA/ahocorasick-domain"
)

// ValidateSet checks the errors that constructing a matcher would return,
// without allocating automata for predicates that will never be evaluated.
func ValidateSet(patterns []string, typ consts.RoutingDomainKey) error {
	for _, pattern := range patterns {
		switch typ {
		case consts.RoutingDomainKey_Regex:
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("failed to compile regex: %v", pattern)
			}
		case consts.RoutingDomainKey_Keyword:
			for _, b := range []byte(pattern) {
				if !ahocorasick.IsValidChar(b) {
					return fmt.Errorf("char out of range: %c", b)
				}
			}
		case consts.RoutingDomainKey_Full, consts.RoutingDomainKey_Suffix:
			// The matcher skips invalid full/suffix patterns without failing.
		default:
			return fmt.Errorf("unknown RoutingDomainKey: %v", typ)
		}
	}
	return nil
}
