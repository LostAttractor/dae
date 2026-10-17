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
	dns "github.com/miekg/dns"
)

// Explain only evaluates immutable matchers and edits private header/URL copies.
// It deliberately never enters Wrap, script execution or cache lookup paths.
func (e *Engine) Explain(ctx context.Context, input api.ExplainRequest) (result plugin.Explanation) {
	ctx = withRegexBudget(ctx)
	wait, cancel := context.WithTimeout(ctx, e.options.ScriptTimeout)
	release, err := e.acquire(wait, "diagnostics")
	cancel()
	if err != nil {
		return plugin.Explanation{Complete: false, Steps: []api.ExplainStep{{ID: "budget", Stage: "surge", Status: "unknown", Match: "unknown", Reason: traceErrorReason(err)}}}
	}
	defer release()
	defer func() {
		if err := regexBudgetError(ctx); err != nil {
			result.Complete = false
			result.Steps = append(result.Steps, api.ExplainStep{ID: "budget", Stage: "surge", Status: "unknown", Match: "unknown", Reason: traceErrorReason(err)})
			e.metrics.skip("diagnostics", traceErrorReason(err))
		}
	}()
	if input.Kind == "dns" {
		return e.explainDNS(ctx)
	}
	result = plugin.Explanation{Complete: true}
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
		if err := regexBudgetError(ctx); err != nil {
			step.Status, step.Match, step.Reason = "unknown", "unknown", traceErrorReason(err)
			result.Complete = false
		} else if result.Terminal {
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
			if regexBudgetError(ctx) != nil {
				result.Complete = false
				return result
			}
			if rule.Type != "http-request" {
				continue
			}
			hit := rule.Match(ctx, value.URL)
			step := appendStep(module, "request_header", i, rule.Pattern+" -> "+rule.Action+" "+rule.Field, hit)
			if hit && result.Complete {
				if err := rule.Apply(ctx, headers); err != nil {
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
	selectedModule, selectedRule := scoped.firstURLRewrite(ctx, value.URL)
	rewritten := false
	for _, module := range scoped.options.Modules {
		for i, rule := range module.URLRewrites {
			if regexBudgetError(ctx) != nil {
				result.Complete = false
				return result
			}
			hit := module == selectedModule && i == selectedRule
			step := appendStep(module, "url", i, rule.Pattern+" -> "+rule.Type+" "+rule.Replacement, hit)
			if rewritten {
				step.Status, step.Match, step.Reason = "not_reached", "unknown", "earlier_url_rule"
				continue
			}
			if !hit || !result.Complete || result.Terminal {
				continue
			}
			rewritten = true
			target, err := rule.Rewrite(ctx, value.URL)
			if err != nil {
				step.Status, step.Reason, result.Complete = "unknown", "rewrite_error: "+err.Error(), false
				continue
			}
			step.Targets, step.Action = []string{target}, rule.Type
			privateRequest := &http.Request{URL: u, Host: value.Host, Header: headers}
			response, err := applyURLRewrite(privateRequest, rule, target)
			if err != nil {
				step.Status, step.Reason, result.Complete = "unknown", "rewrite_error: "+err.Error(), false
			} else {
				value.URL, value.Host = privateRequest.URL.String(), privateRequest.Host
				result.Terminal = response != nil
			}
		}
	}
	for _, module := range scoped.options.Modules {
		for i, rule := range module.MapLocals {
			if regexBudgetError(ctx) != nil {
				result.Complete = false
				return result
			}
			hit := rule.Match(ctx, value.URL)
			step := appendStep(module, "map_local", i, rule.Pattern, hit)
			if hit && result.Complete && !result.Terminal {
				step.Action, step.Reason = "local_response", fmt.Sprintf("local_status_%d", rule.Status)
				result.Terminal = true
			}
		}
	}
	for _, module := range scoped.options.Modules {
		for i, rule := range module.BodyRewrites {
			if regexBudgetError(ctx) != nil {
				result.Complete = false
				return result
			}
			hit := rule.Match(ctx, value.URL)
			step := appendStep(module, rule.Type+"_body", i, rule.Pattern, hit)
			if hit && !result.Terminal {
				step.Status, step.Reason = "unknown", "body_required"
				if rule.Type == "http-request" {
					result.Complete = false
				}
			}
		}
	}
	urls := []string{value.URL}
	if target, err := url.Parse(value.URL); err == nil {
		var sni string
		if input.Flow.SNI != nil {
			sni = *input.Flow.SNI
		}
		urls = scriptMatchURLs(target, value.Host, sni)
	}
	selected := make(map[string]bool)
	for _, module := range scoped.options.Modules {
		for i, script := range module.Scripts {
			if regexBudgetError(ctx) != nil {
				result.Complete = false
				return result
			}
			hit := slices.ContainsFunc(urls, func(rawURL string) bool { return script.Match(ctx, rawURL) })
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

func (e *Engine) explainDNS(ctx context.Context) plugin.Explanation {
	result := plugin.Explanation{Complete: true}
	request, _ := plugin.DiagnosticDNSRequest(ctx)
	query := request.MessageCopy()
	if query == nil || len(query.Question) != 1 {
		result.Complete = false
		return result
	}
	if !hostDNSPacket(request.DNSPacket) {
		result.DNS = query
		result.Steps = append(result.Steps, api.ExplainStep{ID: "question", Stage: "dns_host", Expression: "DNS question", Status: "skipped", Match: "miss", Reason: "unsupported_dns_question"})
		return result
	}

	seen := make(map[string]bool)
	for range 16 {
		name := strings.TrimSuffix(strings.ToLower(query.Question[0].Name), ".")
		if seen[name] {
			result.Complete = false
			result.Steps = append(result.Steps, api.ExplainStep{ID: "alias_loop", Stage: "dns_host", Expression: name, Status: "error", Match: "match", Reason: "alias_loop"})
			return result
		}
		seen[name] = true
		var matched *HostEntry
		for _, module := range e.options.Modules {
			for i := range module.DNSHosts {
				if regexBudgetError(ctx) != nil {
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
			result.DNS = query
			return result
		}
		if len(matched.Addresses) != 0 {
			result.Terminal = true
			request.DNSPacket = plugin.DNSMessage(query)
			result.DNS = hostAddressResponse(&plugin.DNSExchange{DNSRequest: request}, matched.Addresses, 60).MessageCopy()
			return result
		}
		if matched.Alias != "" {
			if query.Question[0].Qtype == dns.TypeCNAME {
				result.Terminal = true
				response := new(dns.Msg).SetReply(query)
				response.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: matched.Alias}}
				result.DNS = response
				return result
			}
			query.Question[0].Name = matched.Alias
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
