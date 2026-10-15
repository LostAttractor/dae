// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/daeuniverse/dae/plugins/surge/internal/jq"
	"github.com/dlclark/regexp2"
)

// BodyRewrite applies a jq filter or consecutive text replacements before scripts.
// jq evaluation belongs to the plugin's memory constrained worker pool.
type BodyRewrite struct {
	Type         string
	Pattern      string
	pattern      *regexp2.Regexp
	expression   string
	jq           *jq.Pool
	replacements []bodyReplacement
}

func (r BodyRewrite) Match(rawURL string) bool { return matchPattern(r.pattern, rawURL) }

func parseBodyRewrite(line string, warnings *[]string) (*BodyRewrite, error) {
	fields, err := rewriteFields(line)
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("Body Rewrite requires a type, URL pattern and expression")
	}
	kind := strings.TrimSuffix(fields[0], "-jq")
	if kind != "http-request" && kind != "http-response" {
		*warnings = append(*warnings, fmt.Sprintf("unsupported Body Rewrite type %q is ignored", fields[0]))
		return nil, nil
	}
	jq := strings.HasSuffix(fields[0], "-jq")
	if jq && len(fields) != 3 || !jq && (len(fields) < 4 || len(fields)%2 != 0) {
		return nil, fmt.Errorf("Body Rewrite requires a URL pattern and a jq expression or regex/replacement pairs")
	}
	rule := &BodyRewrite{Type: kind, Pattern: fields[1]}
	rule.pattern, err = compilePattern(rule.Pattern)
	if err != nil {
		return nil, fmt.Errorf("Body Rewrite URL pattern: %w", err)
	}
	if !jq {
		for i := 2; i < len(fields); i += 2 {
			replacement, err := compileBodyReplacement(fields[i], fields[i+1])
			if err != nil {
				return nil, fmt.Errorf("Body Rewrite regex: %w", err)
			}
			rule.replacements = append(rule.replacements, replacement)
		}
		return rule, nil
	}
	expression := fields[2]
	if expression == "" {
		*warnings = append(*warnings, "empty Body Rewrite jq expression is ignored")
		return nil, nil
	}
	// Keep parsing and compilation bounded independently of the module limit.
	if len(expression) > 64<<10 {
		*warnings = append(*warnings, "Body Rewrite jq expression exceeds 64 KiB and is ignored")
		return nil, nil
	}
	rule.expression = expression
	return rule, nil
}

// Apply returns nil when there is no replacement, distinct from an empty body.
// Multiple jq results form a JSON stream separated by newlines.
func (r BodyRewrite) Apply(ctx context.Context, body []byte, limit int64, budget *membuffer.Budget) (*membuffer.View, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, membuffer.ErrTooLarge
	}
	if len(r.replacements) != 0 {
		return r.replaceText(ctx, body, limit, budget)
	}
	return r.jq.Apply(ctx, r.expression, body, limit, budget)
}

type bodyRewriteWriter struct {
	membuffer.Buffer
	ctx context.Context
}

func (w *bodyRewriteWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.Buffer.Write(p)
}
