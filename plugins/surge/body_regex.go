// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/dlclark/regexp2"
)

type bodyReplacement struct {
	pattern *regexp2.Regexp
	parts   []bodyReplacementPart
}

type bodyReplacementPart struct {
	text  string
	group int // -1 denotes literal text.
}

var bodyReplacementToken = regexp.MustCompile(`\$(\$|&|[0-9]{1,2}|\{[^}]+\})`)

func compileBodyReplacement(pattern, template string) (bodyReplacement, error) {
	re, err := regexp2.Compile(pattern, regexp2.ECMAScript|regexp2.Multiline)
	if err != nil {
		return bodyReplacement{}, err
	}
	re.MatchTimeout = regexTimeout
	r := bodyReplacement{pattern: re}
	groupNumber := func(name string) int {
		if name[0] >= '0' && name[0] <= '9' {
			if number, err := strconv.Atoi(name); err == nil && re.GroupNameFromNumber(number) != "" {
				return number
			}
			return -1
		}
		return re.GroupNumberFromName(name)
	}
	literal := func(text string) {
		if text != "" {
			r.parts = append(r.parts, bodyReplacementPart{text: text, group: -1})
		}
	}
	end := 0
	for _, span := range bodyReplacementToken.FindAllStringIndex(template, -1) {
		literal(template[end:span[0]])
		token := template[span[0]+1 : span[1]]
		switch token {
		case "$":
			literal("$")
		case "&":
			r.parts = append(r.parts, bodyReplacementPart{group: 0})
		default:
			name := strings.TrimSuffix(strings.TrimPrefix(token, "{"), "}")
			group := groupNumber(name)
			// ECMAScript uses the longest existing numeric group: $12 may mean $1 + "2".
			for group < 0 && token[0] != '{' && len(name) > 1 {
				name = name[:len(name)-1]
				group = groupNumber(name)
			}
			if group < 0 {
				literal("$" + token)
			} else {
				r.parts = append(r.parts, bodyReplacementPart{group: group})
				if token[0] != '{' {
					literal(token[len(name):])
				}
			}
		}
		end = span[1]
	}
	literal(template[end:])
	return r, nil
}

func (r BodyRewrite) replaceText(ctx context.Context, body []byte, limit int64, budget *membuffer.Budget) (*membuffer.View, error) {
	if !utf8.Valid(body) {
		return nil, fmt.Errorf("Body Rewrite requires valid UTF-8")
	}
	var current *membuffer.View
	defer func() { current.Close() }()
	for _, replacement := range r.replacements {
		next, err := replacement.apply(ctx, body, limit, budget)
		if err != nil {
			return nil, err
		}
		if next != nil {
			current.Close()
			current, body = next, next.Bytes()
		}
	}
	if current == nil {
		return nil, nil
	}
	return current.Clone(), nil
}

func (r bodyReplacement) apply(ctx context.Context, body []byte, limit int64, budget *membuffer.Budget) (*membuffer.View, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	memory, err := budget.Reserve(int64(utf8.RuneCount(body)) * 4)
	if err != nil {
		return nil, err
	}
	defer memory.Close()
	text := bytes.Runes(body)
	match, err := r.pattern.FindRunesMatch(text)
	if err != nil || match == nil {
		return nil, err
	}
	w := &bodyRewriteWriter{ctx: ctx, Limit: limit, Budget: budget}
	defer w.Close()
	end := 0
	for match != nil {
		if err := w.writeRunes(text[end:match.Index]); err != nil {
			return nil, err
		}
		for _, part := range r.parts {
			if part.group < 0 {
				_, err = w.Write([]byte(part.text))
			} else {
				err = w.writeRunes(match.GroupByNumber(part.group).Runes())
			}
			if err != nil {
				return nil, err
			}
		}
		end = match.Index + match.Length
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		match, err = r.pattern.FindNextMatch(match)
		if err != nil {
			return nil, err
		}
	}
	if err := w.writeRunes(text[end:]); err != nil {
		return nil, err
	}
	return w.View(), nil
}

// Encode in chunks so a capture cannot allocate an unbudgeted replacement body.
func (w *bodyRewriteWriter) writeRunes(text []rune) error {
	var buffer [4096]byte
	out := buffer[:0]
	for _, char := range text {
		out = utf8.AppendRune(out, char)
		if len(out) > len(buffer)-utf8.UTFMax {
			if _, err := w.Write(out); err != nil {
				return err
			}
			out = buffer[:0]
		}
	}
	_, err := w.Write(out)
	return err
}
