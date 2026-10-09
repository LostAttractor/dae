// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"fmt"
	"math"
	"net/textproto"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"
)

var moduleArgumentPattern = regexp.MustCompile(`\{\{\{([^{}]+)\}\}\}`)

// Parse parses module text after replacing #!arguments placeholders with their
// defaults and explicit overrides. It does not perform I/O; use Load to resolve
// script-path and populate each script's Source.
func Parse(source string, overrides map[string]string) (*Module, error) {
	metadata, err := ReadMetadata(source)
	if err != nil {
		return nil, err
	}
	m := &Module{Name: metadata.Name}
	env := sync.OnceValue(func() map[string]string {
		values := requirementEnvironment()
		m.requirementKey = fmt.Sprint(values)
		return values
	})
	if metadata.System != "" && !strings.EqualFold(metadata.System, env()["SYSTEM"]) ||
		metadata.Requirement != "" && !checkRequirement(metadata.Requirement, env(), &m.Warnings) {
		m.disabled = true
		return m, nil
	}
	arguments, err := metadata.resolveArguments(overrides)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimPrefix(source, "\ufeff"), "\n")
	section := ""
	warnedSections := make(map[string]bool)
	for i, line := range lines {
		lineNumber := i + 1
		line = strings.TrimSpace(line)
		_, conditional := lineRequirement(line, "#!REQUIREMENT")
		if line == "" || strings.HasPrefix(line, "#") && !conditional || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		var unknownArgument string
		line = moduleArgumentPattern.ReplaceAllStringFunc(line, func(token string) string {
			key := token[3 : len(token)-3]
			if value, ok := arguments[key]; ok {
				return value
			}
			unknownArgument = key
			return token
		})
		if unknownArgument != "" {
			return nil, fmt.Errorf("module line %d: undefined argument %q", lineNumber, unknownArgument)
		}
		line = moduleLine(strings.TrimSpace(line), env, &m.Warnings)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		var err error
		switch section {
		case "general":
			key, value, ok := strings.Cut(line, "=")
			key = strings.ToLower(strings.TrimSpace(key))
			if !ok {
				err = fmt.Errorf("General directive requires key=value")
			} else if key == "use-local-host-item-for-proxy" {
				m.UseHostsForProxy, err = parseBool(strings.TrimSpace(value))
			} else {
				m.Warnings = append(m.Warnings, fmt.Sprintf("unsupported General directive %q is ignored", key))
			}
		case "host":
			err = parseHost(line, m)
		case "script":
			if len(m.Scripts)+len(m.TaskScripts) >= 256 {
				return nil, fmt.Errorf("module contains more than 256 scripts")
			}
			var script *Script
			script, err = parseScript(line, &m.Warnings, &m.Ignored)
			if script != nil {
				if script.Type == "cron" || script.Type == "generic" {
					if slices.ContainsFunc(m.TaskScripts, func(existing Script) bool { return existing.Name == script.Name }) {
						err = fmt.Errorf("duplicate task name %q", script.Name)
					} else {
						m.TaskScripts = append(m.TaskScripts, *script)
					}
				} else {
					m.Scripts = append(m.Scripts, *script)
				}
			}
		case "mitm":
			err = parseMITM(line, m)
		case "map local":
			var rule *MapLocal
			rule, err = parseMapLocal(line, &m.Warnings)
			if rule != nil {
				m.MapLocals = append(m.MapLocals, *rule)
			}
		case "body rewrite":
			var rule *BodyRewrite
			rule, err = parseBodyRewrite(line, &m.Warnings)
			if rule != nil {
				m.BodyRewrites = append(m.BodyRewrites, *rule)
			}
		case "rule":
			var rule *ModuleRule
			rule, err = parseModuleRule(line, &m.Warnings)
			if rule != nil {
				m.Rules = append(m.Rules, *rule)
			}
		case "url rewrite":
			var rewrite *URLRewrite
			rewrite, err = parseURLRewrite(line, &m.Warnings)
			if rewrite != nil {
				m.URLRewrites = append(m.URLRewrites, *rewrite)
			}
		case "header rewrite":
			var rewrite *HeaderRewrite
			rewrite, err = parseHeaderRewrite(line, &m.Warnings)
			if rewrite != nil {
				m.HeaderRewrites = append(m.HeaderRewrites, *rewrite)
			}
		default:
			if !warnedSections[section] {
				m.Warnings = append(m.Warnings, fmt.Sprintf("unsupported section [%s]; its directives are ignored", section))
				warnedSections[section] = true
			}
		}
		if err != nil {
			return nil, fmt.Errorf("module line %d: %w", lineNumber, err)
		}
	}
	for _, host := range m.DNSHosts {
		if host.Script == "" {
			continue
		}
		found := false
		for _, script := range m.Scripts {
			found = found || script.Name == host.Script && script.Type == "dns"
		}
		if !found {
			return nil, fmt.Errorf("Host references missing DNS script %q", host.Script)
		}
	}
	return m, nil
}

func parseScript(line string, warnings, ignored *[]string) (*Script, error) {
	name, options, ok := strings.Cut(line, "=")
	if !ok || strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("script must have a name and key=value parameters")
	}
	params, err := parseScriptParameters(options)
	if err != nil {
		return nil, err
	}
	s := &Script{Name: strings.TrimSpace(name), Type: params["type"], Path: params["script-path"], Pattern: params["pattern"], Argument: params["argument"], MaxSize: DefaultScriptMaxSize}
	_, s.ArgumentSet = params["argument"]
	if value, exists := params["enable"]; exists {
		enabled, err := parseBool(value)
		if err != nil {
			return nil, fmt.Errorf("script %q parameter enable: %w", s.Name, err)
		}
		if !enabled {
			return nil, nil
		}
	}
	if s.Type == "" {
		s.Type = "generic"
	}
	if s.Type != "http-request" && s.Type != "http-response" && s.Type != "dns" && s.Type != "cron" && s.Type != "generic" {
		*warnings = append(*warnings, fmt.Sprintf("script %q: unsupported type %q; script is ignored", s.Name, s.Type))
		return nil, nil
	}
	if s.Path == "" {
		return nil, fmt.Errorf("script %q requires script-path", s.Name)
	}
	if s.Type == "http-request" || s.Type == "http-response" {
		if s.Pattern == "" {
			return nil, fmt.Errorf("script %q requires pattern", s.Name)
		}
		s.pattern, err = compilePattern(s.Pattern)
		if err != nil {
			return nil, fmt.Errorf("script %q pattern: %w", s.Name, err)
		}
	}
	if s.Type == "cron" {
		s.CronExp = params["cronexp"]
		s.schedule, err = parseCronSchedule(s.CronExp)
		if err != nil {
			return nil, fmt.Errorf("script %q cronexp: %w", s.Name, err)
		}
	}
	for key, value := range params {
		switch key {
		case "type", "script-path", "pattern", "argument", "enable":
		case "cronexp":
			if s.Type != "cron" {
				*warnings = append(*warnings, fmt.Sprintf("script %q: cronexp is only used by cron scripts", s.Name))
			}
		case "script-update-interval", "debug", "img-url", "wake-system":
			*ignored = append(*ignored, fmt.Sprintf("script %q: unsupported parameter %q is ignored", s.Name, key))
		case "engine":
			switch strings.ToLower(value) {
			case "auto", "jsc":
			case "webview":
				appendModuleWarning(warnings, "engine=webview scripts run in QuickJS with supported compatibility APIs; a browser WebView is not provided")
			default:
				err = fmt.Errorf("unknown JavaScript engine %q", value)
			}
		case "requires-body":
			s.RequiresBody, err = parseBool(value)
		case "binary-body-mode":
			s.BinaryBodyMode, err = parseBool(value)
		case "full-header-mode":
			s.FullHeaderMode, err = parseBool(value)
		case "max-size":
			s.MaxSize, err = strconv.ParseInt(value, 10, 64)
			if err == nil && s.MaxSize < -1 {
				err = fmt.Errorf("must be -1, 0, or a positive byte count")
			}
		case "timeout":
			var seconds float64
			seconds, err = strconv.ParseFloat(value, 64)
			if err == nil && (math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 || seconds > 300) {
				err = fmt.Errorf("must be greater than 0 and at most 300 seconds")
			}
			if err == nil {
				s.Timeout = time.Duration(seconds * float64(time.Second))
			}
		default:
			*warnings = append(*warnings, fmt.Sprintf("script %q: unsupported parameter %q is ignored", s.Name, key))
		}
		if err != nil {
			return nil, fmt.Errorf("script %q parameter %s: %w", s.Name, key, err)
		}
	}
	return s, nil
}

func appendModuleWarning(warnings *[]string, message string) {
	if !slices.Contains(*warnings, message) {
		*warnings = append(*warnings, message)
	}
}

func parseBool(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean %q", value)
	}
}

// Delimit parameters by comma + key=, rather than splitting every comma: regex
// quantifiers and Surge's quoted, but internally unescaped, JSON use commas too.
func parseScriptParameters(source string) (map[string]string, error) {
	params := make(map[string]string)
	for strings.TrimSpace(source) != "" {
		key, rest, ok := strings.Cut(strings.TrimSpace(source), "=")
		key = strings.TrimSpace(key)
		if !ok || !parameterKey(key) {
			return nil, fmt.Errorf("invalid script parameter %q", source)
		}
		rest = strings.TrimSpace(rest)
		end := len(rest)
		quoted := len(rest) > 0 && (rest[0] == '"' || rest[0] == '\'')
		closed := !quoted
		for i := 0; i < len(rest); i++ {
			if rest[i] == '\\' {
				i++
				continue
			}
			if quoted && i > 0 && rest[i] == rest[0] {
				next := strings.TrimSpace(rest[i+1:])
				if next == "" || strings.HasPrefix(next, ",") && nextParameter(next[1:]) {
					closed = true
				}
			}
			if rest[i] == ',' && closed && nextParameter(rest[i+1:]) {
				end = i
				break
			}
		}
		if !closed {
			return nil, fmt.Errorf("unterminated quoted script parameter %q", key)
		}
		value := strings.TrimSpace(rest[:end])
		if quoted {
			if len(value) < 2 || value[len(value)-1] != value[0] {
				return nil, fmt.Errorf("invalid quoted script parameter %q", key)
			}
			value = value[1 : len(value)-1]
			// Standard escaped strings are also accepted. The raw nested-quote JSON
			// form remains unchanged when it is not a valid quoted Go/JSON string.
			if unquoted, err := strconv.Unquote(rest[:end]); err == nil {
				value = unquoted
			}
		}
		if _, exists := params[key]; exists {
			return nil, fmt.Errorf("duplicate script parameter %q", key)
		}
		params[key] = value
		if end == len(rest) {
			break
		}
		source = rest[end+1:]
	}
	return params, nil
}

func nextParameter(source string) bool {
	key, _, ok := strings.Cut(strings.TrimSpace(source), "=")
	return ok && parameterKey(strings.TrimSpace(key))
}

func parameterKey(key string) bool {
	if key == "" {
		return false
	}
	for _, ch := range key {
		if ch != '-' && !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') {
			return false
		}
	}
	return true
}

func parseMITM(line string, m *Module) error {
	key, value, ok := strings.Cut(line, "=")
	if !ok {
		return fmt.Errorf("MITM directive requires key=value")
	}
	key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
	if key != "hostname" {
		m.Warnings = append(m.Warnings, fmt.Sprintf("unsupported MITM directive %q is ignored; certificate and TLS settings come from dae", key))
		return nil
	}
	appendHosts, insertHosts := strings.HasPrefix(value, "%APPEND%"), strings.HasPrefix(value, "%INSERT%")
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(value, "%APPEND%"), "%INSERT%"))
	var hosts []string
	for host := range strings.SplitSeq(value, ",") {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if strings.ContainsAny(host, " /\\\t\r\n<>") {
			return fmt.Errorf("invalid MITM hostname %q", host)
		}
		hosts = append(hosts, strings.ToLower(host))
	}
	if insertHosts {
		m.Hostnames = append(hosts, m.Hostnames...)
	} else if appendHosts {
		m.Hostnames = append(m.Hostnames, hosts...)
	} else {
		m.Hostnames = hosts
	}
	return nil
}

func parseURLRewrite(line string, warnings *[]string) (*URLRewrite, error) {
	fields, err := rewriteFields(line)
	if err != nil {
		return nil, err
	}
	if len(fields) < 2 || len(fields) > 3 {
		return nil, fmt.Errorf("URL Rewrite requires space-separated <pattern> <replacement> [type]; got %d fields", len(fields))
	}
	r := &URLRewrite{Pattern: fields[0], Replacement: fields[1], Type: "header"}
	if len(fields) == 3 {
		r.Type = strings.ToLower(fields[2])
	}
	switch r.Type {
	case "header", "302", "307", "reject":
	default:
		*warnings = append(*warnings, fmt.Sprintf("unsupported URL Rewrite type %q is ignored", r.Type))
		return nil, nil
	}
	r.pattern, err = compilePattern(r.Pattern)
	return r, err
}

func parseHeaderRewrite(line string, warnings *[]string) (*HeaderRewrite, error) {
	fields, err := rewriteFields(line)
	if err != nil {
		return nil, err
	}
	r := &HeaderRewrite{Type: "http-request"}
	if len(fields) > 0 && (fields[0] == "http-request" || fields[0] == "http-response") {
		r.Type = fields[0]
		fields = fields[1:]
	}
	if len(fields) < 3 {
		return nil, fmt.Errorf("Header Rewrite requires pattern, action, and field")
	}
	r.Pattern, r.Action, r.Field = fields[0], fields[1], textproto.CanonicalMIMEHeaderKey(fields[2])
	if !httpguts.ValidHeaderFieldName(r.Field) {
		return nil, fmt.Errorf("invalid header field %q", r.Field)
	}
	if r.Field == "Content-Length" || r.Field == "Transfer-Encoding" {
		return nil, fmt.Errorf("Header Rewrite cannot change message framing via %s", r.Field)
	}
	switch r.Action {
	case "header-del":
		if len(fields) != 3 {
			return nil, fmt.Errorf("header-del takes only a field name")
		}
	case "header-add", "header-replace":
		if len(fields) < 4 {
			return nil, fmt.Errorf("%s requires a value", r.Action)
		}
		r.Value = strings.Join(fields[3:], " ")
	case "header-replace-regex":
		if len(fields) != 5 {
			return nil, fmt.Errorf("header-replace-regex requires a value pattern and replacement")
		}
		r.Value, r.Replacement = fields[3], fields[4]
		if r.valuePattern, err = compilePattern(r.Value); err != nil {
			return nil, err
		}
	default:
		*warnings = append(*warnings, fmt.Sprintf("unsupported Header Rewrite action %q is ignored", r.Action))
		return nil, nil
	}
	if !httpguts.ValidHeaderFieldValue(r.Value) || !httpguts.ValidHeaderFieldValue(r.Replacement) {
		return nil, fmt.Errorf("invalid header replacement value")
	}
	r.pattern, err = compilePattern(r.Pattern)
	return r, err
}

// Split rewrite fields while preserving regex escapes and allowing quoted values.
func rewriteFields(source string) ([]string, error) {
	var fields []string
	for strings.TrimSpace(source) != "" {
		source = strings.TrimSpace(source)
		if source[0] == '"' || source[0] == '\'' {
			quote, end := source[0], -1
			for i := 1; i < len(source); i++ {
				if source[i] == '\\' {
					i++
					continue
				}
				if source[i] == quote {
					end = i
					break
				}
			}
			if end == -1 {
				return nil, fmt.Errorf("unterminated quoted rewrite field")
			}
			fields = append(fields, source[1:end])
			source = source[end+1:]
		} else {
			end := strings.IndexAny(source, " \t")
			if end == -1 {
				fields = append(fields, source)
				break
			}
			fields = append(fields, source[:end])
			source = source[end:]
		}
	}
	return fields, nil
}
