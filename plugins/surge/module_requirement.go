// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"cmp"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func requirementEnvironment() map[string]string {
	env := scriptEnvironment()
	name, _ := os.Hostname()
	var system unix.Utsname
	_ = unix.Uname(&system)
	return map[string]string{
		"SYSTEM": env["system"], "SYSTEM_VERSION": unix.ByteSliceToString(system.Release[:]),
		"DEVICE_MODEL": env["device-model"], "DEVICE_NAME": name, "LANGUAGE": env["language"],
	}
}

// Conditions are evaluated before ordinary comments are removed. An unknown
// Surge variable cannot silently turn a conditional directive into an active one.
func moduleLine(line string, env func() map[string]string, warnings *[]string) string {
	if expression, ok := lineRequirement(line, "#!REQUIREMENT"); ok {
		condition, rest, err := cutLineRequirement(strings.TrimSpace(expression))
		if err != nil {
			*warnings = append(*warnings, err.Error())
			return ""
		}
		if !checkRequirement(condition, env(), warnings) {
			return ""
		}
		line = strings.TrimSpace(rest)
	}
	line, comment := splitModuleComment(line)
	for _, prefix := range []string{"#!", "//!"} {
		if directive, ok := strings.CutPrefix(comment, prefix); ok {
			if condition, ok := lineRequirement(directive, "REQUIREMENT"); ok {
				if !checkRequirement(strings.TrimSpace(condition), env(), warnings) {
					return ""
				}
			} else if system, ok := platformRequirement(directive); ok && env()["SYSTEM"] != system {
				return ""
			}
		}
	}
	return line
}

func lineRequirement(line, prefix string) (string, bool) {
	rest, ok := strings.CutPrefix(line, prefix)
	return strings.TrimSpace(rest), ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t')
}

func platformRequirement(directive string) (string, bool) {
	switch strings.TrimSpace(directive) {
	case "IOS-ONLY":
		return "iOS", true
	case "MACOS-ONLY":
		return "macOS", true
	case "TVOS-ONLY":
		return "tvOS", true
	}
	return "", false
}

func cutLineRequirement(source string) (condition, rest string, err error) {
	if strings.HasPrefix(source, `"`) {
		for i := 1; i < len(source); i++ {
			if source[i] == '\\' {
				i++
			} else if source[i] == '"' {
				condition, err = strconv.Unquote(source[:i+1])
				return condition, source[i+1:], err
			}
		}
		return "", "", fmt.Errorf("unterminated line requirement")
	}
	if i := strings.IndexAny(source, " \t"); i >= 0 {
		return source[:i], source[i:], nil
	}
	return "", "", fmt.Errorf("line requirement is missing its directive")
}

func checkRequirement(source string, env map[string]string, warnings *[]string) bool {
	if strings.HasPrefix(source, `"`) {
		unquoted, err := strconv.Unquote(source)
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("requirement skipped: %v", err))
			return false
		}
		source = unquoted
	}
	matched, err := evaluateRequirement(source, env)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("requirement %q skipped: %v", source, err))
	}
	return err == nil && matched
}

var requirementToken = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z_0-9]*|[0-9]+(?:\.[0-9]+)?|'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|>=|=>|<=|=<|==|!=|<>|&&|\|\||[()=!<>])`)

type requirementParser struct {
	tokens []string
	env    map[string]string
}

// Zero removes a CORE_VERSION predicate; negation leaves it ignored.
type requirementMatch int8

const (
	requirementFalse   requirementMatch = -1
	requirementIgnored requirementMatch = 0
	requirementTrue    requirementMatch = 1
)

func evaluateRequirement(source string, env map[string]string) (bool, error) {
	if len(source) > 4096 {
		return false, fmt.Errorf("expression exceeds 4 KiB")
	}
	p := requirementParser{env: env}
	for source = strings.TrimSpace(source); source != ""; source = strings.TrimSpace(source) {
		token := requirementToken.FindString(source)
		if token == "" {
			return false, fmt.Errorf("invalid expression near %q", source)
		}
		p.tokens = append(p.tokens, token)
		source = source[len(token):]
	}
	value, err := p.expression(false)
	if err == nil && len(p.tokens) != 0 {
		err = fmt.Errorf("unexpected token %q", p.tokens[0])
	}
	return value != requirementFalse, err
}

func (p *requirementParser) take() string {
	if len(p.tokens) == 0 {
		return ""
	}
	token := p.tokens[0]
	p.tokens = p.tokens[1:]
	return token
}

// AND binds more tightly than OR; both branches are parsed even when the result
// is known so unsupported conditions are always reported.
func (p *requirementParser) expression(and bool) (requirementMatch, error) {
	next := p.predicate
	if !and {
		next = func() (requirementMatch, error) { return p.expression(true) }
	}
	left, err := next()
	for err == nil && len(p.tokens) != 0 {
		op := strings.ToUpper(p.tokens[0])
		if and && op != "AND" && op != "&&" || !and && op != "OR" && op != "||" {
			break
		}
		p.take()
		var right requirementMatch
		right, err = next()
		if left == requirementIgnored {
			left = right
		} else if right != requirementIgnored {
			if and {
				left = min(left, right)
			} else {
				left = max(left, right)
			}
		}
	}
	return left, err
}

func (p *requirementParser) predicate() (requirementMatch, error) {
	token := p.take()
	if token == "!" || strings.EqualFold(token, "NOT") {
		value, err := p.predicate()
		return -value, err
	}
	if token == "(" {
		value, err := p.expression(false)
		if err == nil && p.take() != ")" {
			err = fmt.Errorf("missing closing parenthesis")
		}
		return value, err
	}
	left, err := p.value(token)
	if err != nil {
		return requirementIgnored, err
	}
	op := strings.ToUpper(p.take())
	rightToken := p.take()
	right, err := p.value(rightToken)
	if err != nil {
		return requirementIgnored, err
	}
	matched, err := compareRequirement(token, left, op, rightToken, right)
	if token == "CORE_VERSION" || rightToken == "CORE_VERSION" {
		return requirementIgnored, err
	}
	if matched {
		return requirementTrue, err
	}
	return requirementFalse, err
}

func compareRequirement(token, left, op, rightToken, right string) (bool, error) {
	order := cmp.Compare(left, right)
	if token[0] >= '0' && token[0] <= '9' && rightToken[0] >= '0' && rightToken[0] <= '9' {
		a, _ := strconv.ParseFloat(left, 64)
		b, _ := strconv.ParseFloat(right, 64)
		order = cmp.Compare(a, b)
	}
	switch op {
	case "=", "==":
		return order == 0, nil
	case "!=", "<>":
		return order != 0, nil
	case ">":
		return order > 0, nil
	case "<":
		return order < 0, nil
	case ">=", "=>":
		return order >= 0, nil
	case "<=", "=<":
		return order <= 0, nil
	case "BEGINSWITH":
		return strings.HasPrefix(left, right), nil
	case "ENDSWITH":
		return strings.HasSuffix(left, right), nil
	case "CONTAINS":
		return strings.Contains(left, right), nil
	case "LIKE", "MATCHES":
		pattern := right
		if op == "LIKE" {
			pattern = strings.NewReplacer(`\*`, ".*", `\?`, ".").Replace(regexp.QuoteMeta(pattern))
		}
		re, err := compilePattern("^(?:" + pattern + ")$")
		if err != nil {
			return false, err
		}
		return re.MatchString(left)
	default:
		return false, fmt.Errorf("unsupported operator %q", op)
	}
}

func (p *requirementParser) value(token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("missing value")
	}
	if token == "CORE_VERSION" {
		return "", nil
	}
	if token[0] == '\'' || token[0] == '"' {
		value := token[1 : len(token)-1]
		return strings.NewReplacer(`\`+token[:1], token[:1], `\\`, `\`).Replace(value), nil
	}
	if token[0] >= '0' && token[0] <= '9' {
		return token, nil
	}
	if value, ok := p.env[token]; ok {
		return value, nil
	}
	return "", fmt.Errorf("unsupported variable %q", token)
}
