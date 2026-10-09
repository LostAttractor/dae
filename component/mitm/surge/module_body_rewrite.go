// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"strings"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/dlclark/regexp2"
	"github.com/itchyny/gojq"
)

// BodyRewrite applies a jq filter or consecutive text replacements before scripts.
// QuickJS's heap limit does not govern these evaluators.
type BodyRewrite struct {
	Type         string
	Pattern      string
	pattern      *regexp2.Regexp
	code         *gojq.Code
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
	// Keep parsing and compilation bounded independently of the module limit.
	if len(expression) > 64<<10 {
		*warnings = append(*warnings, "Body Rewrite jq expression exceeds 64 KiB and is ignored")
		return nil, nil
	}
	query, err := gojq.Parse(expression)
	if err == nil {
		// The default compiler exposes no environment, filesystem module loader,
		// or input iterator. Never enable those host capabilities for modules.
		rule.code, err = gojq.Compile(query)
	}
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("invalid Body Rewrite jq expression for %q is ignored: %v", rule.Pattern, err))
		return nil, nil
	}
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
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var input any
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("Body Rewrite requires valid JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("Body Rewrite requires one JSON document")
	}
	writer := &bodyRewriteWriter{ctx: ctx, Limit: limit, Budget: budget}
	defer writer.Close()
	iterator := r.code.RunWithContext(ctx, input)
	for {
		value, ok := iterator.Next()
		if !ok {
			break
		}
		if err, ok := value.(error); ok {
			return nil, fmt.Errorf("Body Rewrite jq: %w", err)
		}
		if writer.Len() != 0 {
			if _, err := writer.Write([]byte{'\n'}); err != nil {
				return nil, err
			}
		}
		if err := jsonv2.MarshalWrite(writer, value, jsonv2.Deterministic(true)); err != nil {
			return nil, fmt.Errorf("Body Rewrite jq output: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if writer.Len() == 0 {
		return nil, nil
	}
	return writer.View(), nil
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
