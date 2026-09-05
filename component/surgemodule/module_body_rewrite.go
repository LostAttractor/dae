// SPDX-License-Identifier: AGPL-3.0-only

package surgemodule

import (
	"bytes"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"

	"github.com/dlclark/regexp2"
	"github.com/itchyny/gojq"
)

// BodyRewrite is a precompiled response-body jq filter. gojq uses a separate Go
// evaluator, not QuickJS: input/output sizes and execution time are bounded by
// the proxy, but QuickJS's memory_limit does not govern jq intermediate values.
type BodyRewrite struct {
	Pattern string
	pattern *regexp2.Regexp
	code    *gojq.Code
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
	if fields[0] != "http-response-jq" {
		*warnings = append(*warnings, fmt.Sprintf("unsupported Body Rewrite type %q is ignored; only http-response-jq is supported", fields[0]))
		return nil, nil
	}
	if len(fields) != 3 {
		return nil, fmt.Errorf("http-response-jq requires a URL pattern and one quoted jq expression")
	}
	rule := &BodyRewrite{Pattern: fields[1]}
	expression := fields[2]
	rule.pattern, err = compilePattern(rule.Pattern)
	if err != nil {
		return nil, fmt.Errorf("Body Rewrite URL pattern: %w", err)
	}
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

// Apply returns nil when jq produces no output, which means keep the original
// body. JSON numbers retain their precision. Multiple jq results form a JSON
// stream, separated by newlines, as with jq's standard output.
func (r BodyRewrite) Apply(ctx context.Context, body []byte, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.code == nil {
		return nil, fmt.Errorf("Body Rewrite jq expression is not compiled")
	}
	if int64(len(body)) > limit {
		return nil, errBodyTooLarge
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
	writer := &bodyRewriteWriter{ctx: ctx, limit: limit}
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
	return writer.Bytes(), nil
}

type bodyRewriteWriter struct {
	bytes.Buffer
	ctx   context.Context
	limit int64
}

func (w *bodyRewriteWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(p)) > w.limit-int64(w.Len()) {
		return 0, errBodyTooLarge
	}
	return w.Buffer.Write(p)
}
