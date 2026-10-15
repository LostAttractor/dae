// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// Validate uses the real matcher builders without resources or interface
// subscriptions. Resource contents (including their expanded size) are checked
// during preparation; every literal predicate and outbound is checked here.
func Validate(conf *Config) error {
	request, err := routing.ApplyRulesOptimizers(conf.Routing.Request.Rules, &routing.AliasOptimizer{}, resourceReferences{})
	if err != nil {
		return err
	}
	response, err := routing.ApplyRulesOptimizers(conf.Routing.Response.Rules, resourceReferences{})
	if err != nil {
		return err
	}
	_, err = New(conf, request, response, &NewOption{})
	return err
}

// Use one representative expansion for each deferred resource. Retain its
// containing function and rule so their syntax and outbound still get checked.
// ApplyRulesOptimizers clones before calling this; Spec is never mutated.
type resourceReferences struct{}

func (resourceReferences) Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error) {
	for _, rule := range rules {
		for _, f := range rule.AndFunctions {
			for _, param := range f.Params {
				domain := false
				switch param.Key {
				case "geosite":
					domain = true
				case "geoip":
				case "mmdb":
					field, value, ok := strings.Cut(param.Val, "=")
					if !ok || field == "" || value == "" {
						return nil, fmt.Errorf("invalid mmdb parameter %q: expected <field>=<value>", param.Val)
					}
				case "ext":
					file, code, ok := strings.Cut(param.Val, ":")
					if !ok || file == "" || code == "" {
						return nil, fmt.Errorf("invalid ext parameter %q: expected <filename>:<code>", param.Val)
					}
					switch f.Name {
					case consts.Function_QName:
						domain = true
					case consts.Function_DestIp, consts.Function_SourceIp:
					default:
						return nil, fmt.Errorf("unsupported ext function: %s", f.Name)
					}
				default:
					continue
				}
				if domain {
					param.Key, param.Val = "suffix", "validation.invalid"
				} else {
					param.Key, param.Val = "", "192.0.2.0/24"
				}
			}
		}
	}
	return rules, nil
}
