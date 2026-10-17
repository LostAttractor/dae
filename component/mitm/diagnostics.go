// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"fmt"
	"net/url"
	"slices"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/plugin"
	dnsmessage "github.com/miekg/dns"
)

// Explain reads accepted immutable plans and calls only the optional pure
// capability. A missing capability is an explicit unknown execution boundary.
func (h *Host) Explain(ctx context.Context, request api.ExplainRequest, dns bool) plugin.Explanation {
	result := plugin.Explanation{Complete: true}
	if dns {
		if identity, ok := plugin.DiagnosticDNSRequest(ctx); ok && identity.ContextKey != "" {
			identity.ContextKey = h.dnsContext + identity.ContextKey
			ctx = plugin.WithDiagnosticDNSRequest(ctx, identity)
		}
	}
	if !dns && h.options.DisableHTTP {
		result.Steps = []api.ExplainStep{{ID: "http/disabled", Stage: "configuration", Expression: "HTTP interception", Status: "inactive", Match: "miss", Reason: "http_disabled"}}
		return result
	}
	host := request.Flow.Destination.IP
	if request.Flow.HTTP != nil {
		if u, err := url.Parse(request.Flow.HTTP.URL); err == nil {
			host = u.Hostname()
		}
	}
	if request.Flow.SNI != nil && *request.Flow.SNI != "" {
		host = *request.Flow.SNI
	}
	var query *dnsmessage.Msg
	upstreamSelected := false
	if dns {
		identity, _ := plugin.DiagnosticDNSRequest(ctx)
		query = identity.MessageCopy()
	}

	for _, instance := range h.instances {
		if ctx.Err() != nil {
			result.Complete = false
			return result
		}
		stage := "http_plugin"
		if dns {
			stage = "dns_plugin"
		}
		step := api.ExplainStep{ID: stage + "/" + instance.ID, Stage: stage, Expression: instance.Type + ":" + instance.ID, Status: "not_reached", Match: "miss", Reason: "scope_miss"}
		matched := false
		if dns {
			for _, scope := range instance.plan.DNS {
				matched = matched || scope.Match(query)
			}
			if query == nil && len(instance.plan.DNS) != 0 {
				step.Match, step.Reason = "unknown", "missing_dns_question"
			}
		} else {
			for n, scope := range instance.plan.Scopes {
				decision, allowed := scope.Scope.Decide(host, uint16(request.Flow.Destination.Port))
				matched = matched || allowed
				for i, rule := range scope.Scope {
					hit := rule.Match(host, uint16(request.Flow.Destination.Port))
					condition := api.ExplainCondition{Expression: fmt.Sprintf("scope %d: %s ports=%v exclude=%t", n, rule.Host, rule.Ports, rule.Exclude), Actual: fmt.Sprintf("%s:%d", host, request.Flow.Destination.Port), Expected: rule.Host, Match: "miss", Status: "evaluated", Reason: "host_mismatch"}
					if len(rule.Ports) != 0 && !slices.Contains(rule.Ports, uint16(request.Flow.Destination.Port)) {
						condition.Reason = "port_mismatch"
					}
					if decision >= 0 && i > decision {
						condition.Status = "supplementary"
					}
					if hit {
						condition.Match, condition.Reason = "match", "scope_match"
						if rule.Exclude {
							condition.Reason = "scope_exclusion"
						}
					}
					step.Conditions = append(step.Conditions, condition)
				}
			}
		}
		if matched {
			step.Match, step.Reason = "match", "scope_match"
		}
		if upstreamSelected {
			step.Status, step.Reason = "not_reached", "earlier_upstream_transport"
		} else if result.Terminal {
			step.Reason = "earlier_local_response"
		} else if !result.Complete {
			step.Status, step.Reason = "conditional", "earlier_unknown_plugin"
		} else {
			step.Status = "evaluated"
		}
		result.Steps = append(result.Steps, step)
		if result.Terminal || upstreamSelected {
			continue
		}
		if step.Match == "unknown" {
			result.Complete = false
			continue
		}
		if !matched {
			continue
		}
		if implementation, ok := instance.Plugin.(plugin.Explainer); ok {
			priorComplete := result.Complete
			input := request
			if dns {
				input.Kind = "dns"
			} else {
				input.Kind = "flow"
			}
			output := implementation.Explain(ctx, input)
			for i := range output.Steps {
				output.Steps[i].Parent = step.ID
				output.Steps[i].ID = step.ID + "/" + output.Steps[i].ID
				if !priorComplete {
					output.Steps[i].Status = "conditional"
					output.Steps[i].Reason = "earlier_unknown_plugin: " + output.Steps[i].Reason
				}
			}
			result.Steps = append(result.Steps, output.Steps...)
			result.Complete, result.Terminal = priorComplete && output.Complete, priorComplete && output.Terminal
			if len(output.Dials) != 0 && priorComplete {
				result.Dials = output.Dials
				upstreamSelected = true
			}
			if output.HTTP != nil && priorComplete && output.Complete {
				request.Flow.HTTP, result.HTTP = output.HTTP, output.HTTP
			}
			if output.DNS != nil && priorComplete && output.Complete {
				query, result.DNS = output.DNS, output.DNS
				identity, _ := plugin.DiagnosticDNSRequest(ctx)
				identity.DNSPacket = plugin.DNSMessage(query)
				ctx = plugin.WithDiagnosticDNSRequest(ctx, identity)

			}
		} else {
			result.Steps[len(result.Steps)-1].Status, result.Steps[len(result.Steps)-1].Reason = "unknown", "plugin_explanation_unavailable"
			result.Complete = false
		}
	}
	return result
}
