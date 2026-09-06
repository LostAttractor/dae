// SPDX-License-Identifier: AGPL-3.0-only

// Package surgemodule implements Surge HTTP processing and selected routing features.
package surgemodule

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/dlclark/regexp2"
)

const (
	DefaultScriptTimeout       = 5 * time.Second
	DefaultScriptMaxSize int64 = 1 << 20
	regexTimeout               = 50 * time.Millisecond
)

// Module is an ordered collection of HTTP scripts and rewrite rules. Warnings
// report unexpected or behavior-changing limitations; Ignored lists documented
// unsupported options for trace logging.
type Module struct {
	Name           string
	Hostnames      []string
	Scripts        []Script
	URLRewrites    []URLRewrite
	HeaderRewrites []HeaderRewrite
	MapLocals      []MapLocal
	BodyRewrites   []BodyRewrite
	Rules          []ModuleRule
	Hosts          routing.DestinationRewrites
	Warnings       []string
	Ignored        []string
	source         string
	cacheState     string
}

type Script struct {
	Name, Type, Pattern, Path, Source, Argument string
	RequiresBody, BinaryBodyMode                bool
	MaxSize                                     int64
	Timeout                                     time.Duration // Zero inherits the engine's default.
	pattern                                     *regexp2.Regexp
}

func (s Script) Match(rawURL string) bool { return matchPattern(s.pattern, rawURL) }

type URLRewrite struct {
	Pattern, Replacement, Type string
	pattern                    *regexp2.Regexp
}

func (r URLRewrite) Match(rawURL string) bool { return matchPattern(r.pattern, rawURL) }

// Rewrite substitutes the first match, preserving the unmatched URL suffix.
func (r URLRewrite) Rewrite(rawURL string) (string, error) {
	if r.pattern == nil {
		return rawURL, fmt.Errorf("URL rewrite is not compiled")
	}
	return r.pattern.Replace(rawURL, r.Replacement, -1, 1)
}

type HeaderRewrite struct {
	Type, Pattern, Action, Field, Value, Replacement string
	pattern, valuePattern                            *regexp2.Regexp
}

func (r HeaderRewrite) Match(rawURL string) bool { return matchPattern(r.pattern, rawURL) }

// Apply modifies a header after the caller has matched the direction and URL.
// header-replace, like Surge, only changes an already present header field.
func (r HeaderRewrite) Apply(header http.Header) error {
	field := http.CanonicalHeaderKey(r.Field)
	switch r.Action {
	case "header-add":
		header.Add(field, r.Value)
	case "header-del":
		header.Del(field)
	case "header-replace":
		if _, exists := header[field]; exists {
			header.Set(field, r.Value)
		}
	case "header-replace-regex":
		if r.valuePattern == nil {
			return fmt.Errorf("header rewrite is not compiled")
		}
		values := append([]string(nil), header[field]...)
		for i, value := range values {
			replaced, err := r.valuePattern.Replace(value, r.Replacement, -1, -1)
			if err != nil {
				return err
			}
			if strings.ContainsAny(replaced, "\r\n\x00") {
				return fmt.Errorf("header replacement contains a control character")
			}
			values[i] = replaced
		}
		if len(values) != 0 {
			header[field] = values
		}
	default:
		return fmt.Errorf("unsupported header action %q", r.Action)
	}
	return nil
}

func compilePattern(pattern string) (*regexp2.Regexp, error) {
	re, err := regexp2.Compile(pattern, regexp2.ECMAScript)
	if err != nil {
		return nil, err
	}
	re.MatchTimeout = regexTimeout
	return re, nil
}

func matchPattern(pattern *regexp2.Regexp, value string) bool {
	if pattern == nil {
		return false
	}
	matched, err := pattern.MatchString(value)
	return err == nil && matched
}

// matchConnection applies this module's allowlist without borrowing another
// module's hosts or exclusions. Plain HTTP uses the same host scope as TLS.
func (m *Module) matchConnection(host string, port uint16) bool {
	if m == nil || host == "" {
		return false
	}
	if port == 80 {
		return m.MatchHostname(host)
	}
	return m.MatchHostname(net.JoinHostPort(host, strconv.Itoa(int(port))))
}

// MatchHostname follows Surge's ordered hostname list: the first match wins,
// including a '-' exclusion. A host without a port is treated as sniffed SNI;
// bare hostname entries then match independently of the connection port.
func (m *Module) MatchHostname(host string) bool {
	host, port := splitHostnamePort(host)
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, pattern := range m.Hostnames {
		exclude := strings.HasPrefix(pattern, "-")
		pattern = strings.TrimPrefix(pattern, "-")
		pattern, wantedPort := splitHostnamePort(pattern)
		if wantedPort == "" {
			wantedPort = "443"
		}
		if port != "" && wantedPort != "0" && wantedPort != port {
			continue
		}
		if wildcardHostname(strings.TrimSuffix(strings.ToLower(pattern), "."), host) {
			return !exclude
		}
	}
	return false
}

func splitHostnamePort(host string) (string, string) {
	if name, port, err := net.SplitHostPort(host); err == nil {
		return name, port
	}
	return strings.Trim(host, "[]"), ""
}

// Wildcard matching without regex compilation on the connection path.
func wildcardHostname(pattern, host string) bool {
	p, h, star, backtrack := 0, 0, -1, 0
	for h < len(host) {
		if p < len(pattern) && (pattern[p] == '?' || pattern[p] == host[h]) {
			p++
			h++
			continue
		}
		if p < len(pattern) && pattern[p] == '*' {
			star = p
			p++
			backtrack = h
			continue
		}
		if star < 0 {
			return false
		}
		backtrack++
		h = backtrack
		p = star + 1
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
