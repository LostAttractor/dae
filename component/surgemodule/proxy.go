// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"errors"
	"strings"
	"time"
)

type EngineOptions struct {
	Modules []*Module

	Runtime              *Runtime
	MaxBodySize          int64
	MaxConcurrentScripts int
	ScriptTimeout        time.Duration
	Log                  func(string)
	// Trace receives automatic diagnostics concurrently from connections. A nil
	// callback disables tracing. TraceEnabled optionally avoids formatting when
	// the daemon's current log level filters out these diagnostics.
	Trace        func(string)
	TraceEnabled func() bool
}

// Engine applies module rules to intercepted HTTP connections. Client selection
// and outbound routing are decided by the caller before invoking the plugin.
type Engine struct {
	options EngineOptions
	slots   chan struct{}
}

func NewEngine(o EngineOptions) (*Engine, error) {
	for _, module := range o.Modules {
		if len(module.Scripts) != 0 && o.Runtime == nil {
			return nil, errors.New("surge: HTTP scripts require a QuickJS runtime")
		}
	}
	if o.MaxBodySize <= 0 || o.MaxConcurrentScripts <= 0 || o.ScriptTimeout <= 0 {
		return nil, errors.New("surge: positive body, concurrency and timeout limits are required")
	}
	return &Engine{options: o, slots: make(chan struct{}, o.MaxConcurrentScripts)}, nil
}

// Hostnames returns the union of positive patterns for kernel capture. Local
// exclusions cannot be flattened into this list: Match evaluates them within
// each module after the connection reaches userspace.
func (e *Engine) Hostnames() []string {
	var hosts []string
	seen := make(map[string]bool)
	for _, module := range e.options.Modules {
		for _, host := range module.Hostnames {
			if strings.HasPrefix(host, "-") || seen[host] {
				continue
			}
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// ModuleRules returns supported routing rules in module/profile order.
func (e *Engine) ModuleRules() []ModuleRule {
	var rules []ModuleRule
	for _, module := range e.options.Modules {
		rules = append(rules, module.Rules...)
	}
	return rules
}

// Match checks the destination against module hostnames. Port 80 uses the same
// explicit host allowlist as TLS, for http-request module rules.
func (e *Engine) Match(host string, port uint16) bool {
	if host == "" {
		return false
	}
	for _, module := range e.options.Modules {
		if module.matchConnection(host, port) {
			return true
		}
	}
	return false
}

// forConnection fixes HTTP processing to modules that allow the intercepted
// destination. Rewrites cannot activate a different module by changing URL or
// Host. The connection shares the engine's runtime and concurrency limit.
func (e *Engine) forConnection(host string, port uint16) *Engine {
	scoped := *e
	scoped.options.Modules = nil
	for _, module := range e.options.Modules {
		if module.matchConnection(host, port) {
			scoped.options.Modules = append(scoped.options.Modules, module)
		}
	}
	return &scoped
}

func (e *Engine) log(message string) {
	if e.options.Log != nil {
		e.options.Log(message)
	}
}
