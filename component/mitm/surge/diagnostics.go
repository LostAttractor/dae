// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
)

// Explain only evaluates immutable matchers and edits private header/URL copies.
// It deliberately never enters Wrap, script execution or cache lookup paths.
func (e *Engine) Explain(ctx context.Context, input api.ExplainRequest) plugin.Explanation {
	if input.Kind == "dns" {
		return e.explainDNS(ctx, input)
	}
	result := plugin.Explanation{Complete: true}
	if input.Flow.HTTP == nil {
		result.Complete = false
		result.Steps = append(result.Steps, api.ExplainStep{ID: "request", Stage: "surge", Expression: "HTTP request", Status: "unknown", Match: "unknown", Reason: "missing_http_request"})
		return result
	}
	value := *input.Flow.HTTP
	value.Headers = http.Header(value.Headers).Clone()
	if value.Headers == nil {
		value.Headers = make(map[string][]string)
	}
	u, _ := url.Parse(value.URL)
	if u == nil {
		result.Complete = false
		return result
	}
	host := u.Hostname()
	if input.Flow.SNI != nil && *input.Flow.SNI != "" {
		host = *input.Flow.SNI
	}
	scoped := e.forConnection(host, uint16(input.Flow.Destination.Port))
	appendStep := func(module *Module, kind string, index int, expression string, hit bool) *api.ExplainStep {
		step := api.ExplainStep{ID: fmt.Sprintf("%s/%s/%d", module.Name, kind, index), Stage: "surge/" + kind, Expression: expression, Status: "evaluated", Match: "miss", Reason: "pattern_mismatch", Sources: []api.DiagnosticSource{{File: module.source, Expression: module.Name + ": " + expression}}}
		if hit {
			step.Match, step.Reason = "match", "pattern_match"
		}
		if result.Terminal {
			step.Status, step.Reason = "not_reached", "earlier_local_response"
		} else if !result.Complete {
			step.Status, step.Reason = "conditional", "earlier_dynamic_action"
		}
		result.Steps = append(result.Steps, step)
		return &result.Steps[len(result.Steps)-1]
	}
	for _, module := range e.options.Modules {
		if !module.matchConnection(host, uint16(input.Flow.Destination.Port)) {
			result.Steps = append(result.Steps, api.ExplainStep{ID: module.Name + "/scope", Stage: "surge/module", Expression: module.Name, Status: "skipped", Match: "miss", Reason: "module_scope_miss"})
		}
	}
	headers := http.Header(value.Headers)
	headers.Set("Host", cmp.Or(value.Host, u.Host))
	for _, module := range scoped.options.Modules {
		for i, rule := range module.HeaderRewrites {
			if ctx.Err() != nil {
				result.Complete = false
				return result
			}
			if rule.Type != "http-request" {
				continue
			}
			hit := rule.Match(value.URL)
			step := appendStep(module, "request_header", i, rule.Pattern+" -> "+rule.Action+" "+rule.Field, hit)
			if hit && result.Complete {
				if err := rule.Apply(headers); err != nil {
					step.Reason, step.Status, result.Complete = "rewrite_error: "+err.Error(), "unknown", false
				}
			}
		}
	}
	value.Host = headers.Get("Host")
	if value.Host == "" {
		value.Host = cmp.Or(input.Flow.HTTP.Host, u.Host)
	}
	headers.Del("Host")
	rewritten := false
	for _, module := range scoped.options.Modules {
		for i, rule := range module.URLRewrites {
			if ctx.Err() != nil {
				result.Complete = false
				return result
			}
			hit := rule.Match(value.URL)
			step := appendStep(module, "url", i, rule.Pattern+" -> "+rule.Type+" "+rule.Replacement, hit)
			if rewritten {
				step.Status, step.Reason = "not_reached", "earlier_url_rule"
				continue
			}
			if !hit || !result.Complete || result.Terminal {
				continue
			}
			rewritten = true
			target, err := rule.Rewrite(value.URL)
			if err != nil {
				step.Status, step.Reason, result.Complete = "unknown", "rewrite_error: "+err.Error(), false
				continue
			}
			step.Targets, step.Action = []string{target}, rule.Type
			if rule.Type == "header" {
				value.URL = target
				parsed, err := url.Parse(target)
				if err != nil || parsed.Host == "" {
					result.Complete = false
				} else {
					value.Host = parsed.Host
				}
			} else {
				result.Terminal = true
			}
		}
	}
	for _, module := range scoped.options.Modules {
		for i, rule := range module.MapLocals {
			hit := rule.Match(value.URL)
			step := appendStep(module, "map_local", i, rule.Pattern, hit)
			if hit && result.Complete && !result.Terminal {
				step.Action, step.Reason = "local_response", fmt.Sprintf("local_status_%d", rule.Status)
				result.Terminal = true
			}
		}
	}
	for _, module := range scoped.options.Modules {
		for i, rule := range module.BodyRewrites {
			hit := rule.Match(value.URL)
			step := appendStep(module, rule.Type+"_body", i, rule.Pattern, hit)
			if hit && !result.Terminal {
				step.Status, step.Reason = "unknown", "body_required"
				if rule.Type == "http-request" {
					result.Complete = false
				}
			}
		}
	}
	selected := make(map[string]bool)
	for _, module := range scoped.options.Modules {
		for i, script := range module.Scripts {
			if ctx.Err() != nil {
				result.Complete = false
				return result
			}
			hit := script.Match(value.URL)
			for _, alias := range []string{value.Host, func() string {
				if input.Flow.SNI != nil {
					return *input.Flow.SNI
				}
				return ""
			}()} {
				if alias != "" {
					parsed, err := url.Parse(value.URL)
					if err == nil {
						parsed.Host = alias
						hit = hit || script.Match(parsed.String())
					}
				}
			}
			step := appendStep(module, script.Type, i, script.Name+": "+script.Pattern, hit)
			if selected[script.Type] {
				step.Status, step.Reason = "not_reached", "earlier_script"
				continue
			}
			if hit && !result.Terminal {
				selected[script.Type] = true
				step.Status, step.Reason, step.Action = "unknown", "script_execution_required", "script"
				if script.Type == "http-request" {
					result.Complete = false
				}
			}
		}
	}
	result.HTTP = &value
	return result
}

func (e *Engine) explainDNS(ctx context.Context, input api.ExplainRequest) plugin.Explanation {
	result := plugin.Explanation{Complete: true}
	if input.DNS == nil {
		result.Complete = false
		return result
	}
	query := *input.DNS
	query.AnswerIPs = slices.Clone(query.AnswerIPs)
	seen := make(map[string]bool)
	for range 16 {
		name := strings.TrimSuffix(strings.ToLower(query.Name), ".")
		if seen[name] {
			result.Complete = false
			result.Steps = append(result.Steps, api.ExplainStep{ID: "alias_loop", Stage: "dns_host", Expression: name, Status: "error", Match: "match", Reason: "alias_loop"})
			return result
		}
		seen[name] = true
		var matched *HostEntry
		for _, module := range e.options.Modules {
			for i := range module.DNSHosts {
				if ctx.Err() != nil {
					result.Complete = false
					return result
				}
				rule := &module.DNSHosts[i]
				step := api.ExplainStep{ID: fmt.Sprintf("%s/%s/%d", module.Name, name, i), Stage: "dns_host", Expression: fmt.Sprint(*rule), Status: "evaluated", Match: "miss", Reason: "hostname_mismatch"}
				if rule.Match(name) {
					step.Match, step.Reason = "match", "hostname_match"
				}
				if matched != nil {
					step.Status, step.Reason = "not_reached", "earlier_host_rule"
				} else if step.Match == "match" {
					matched = rule
					step.Status = "selected"
				}
				result.Steps = append(result.Steps, step)
			}
		}
		if matched == nil {
			result.DNS = &query
			return result
		}
		if len(matched.Addresses) != 0 {
			result.Terminal = true
			for _, address := range matched.Addresses {
				if (query.Type == "" || strings.EqualFold(query.Type, "A")) && address.Is4() || strings.EqualFold(query.Type, "AAAA") && address.Is6() || strings.EqualFold(query.Type, "ANY") {
					query.AnswerIPs = append(query.AnswerIPs, address.String())
				}
			}
			result.DNS = &query
			return result
		}
		if matched.Alias != "" {
			if strings.EqualFold(query.Type, "CNAME") {
				result.Terminal = true
				return result
			}
			query.Name = matched.Alias
			continue
		}
		reason := "assigned_upstream"
		if matched.Script != "" {
			reason = "script_execution_required"
		}
		result.Steps = append(result.Steps, api.ExplainStep{ID: name + "/action", Stage: "dns_host", Expression: cmp.Or(matched.Script, strings.Join(matched.Servers, ", ")), Status: "unknown", Match: "match", Reason: reason, Targets: matched.Servers})
		result.Complete = false
		return result
	}
	result.Complete = false
	return result
}
