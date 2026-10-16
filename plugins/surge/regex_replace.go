// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/dlclark/regexp2/syntax"
)

const maxRegexReplacementBytes = 1 << 20

// URL/header replacement keeps regexp2's capture and special-token semantics,
// including sparse groups and Unicode indices, with bounded output storage.
func replacePattern(ctx context.Context, pattern *regexp2.Regexp, value, replacement string, count int) (string, error) {
	numbers := pattern.GetGroupNumbers()
	caps, names := make(map[int]int), make(map[string]int)
	for i, number := range numbers {
		caps[number] = i
		names[pattern.GroupNameFromNumber(number)] = number
	}
	data, err := syntax.NewReplacerData(replacement, caps, len(numbers), names, syntax.ECMAScript)
	if err != nil {
		return "", err
	}
	text := []rune(value)
	var out strings.Builder
	write := func(value string) error {
		if len(value) > maxRegexReplacementBytes-out.Len() {
			return errors.New("regex replacement exceeds 1 MiB")
		}
		out.WriteString(value)
		return nil
	}
	end := 0
	matched := false
	for match, err := range regexBudgetFor(ctx).matches(ctx, pattern, text, count) {
		if err != nil {
			return "", err
		}
		matched = true
		if err := write(string(text[end:match.Index])); err != nil {
			return "", err
		}
		groups := match.Groups()
		for _, rule := range data.Rules {
			var part string
			switch {
			case rule >= 0:
				part = data.Strings[rule]
			case rule <= -5:
				part = groups[-5-rule].String()
			case rule == -4:
				part = string(text[:match.Index])
			case rule == -3:
				part = string(text[match.Index+match.Length:])
			case rule == -2:
				part = groups[len(groups)-1].String()
			case rule == -1:
				part = value
			}
			if err := write(part); err != nil {
				return "", err
			}
		}
		end = match.Index + match.Length
	}
	if !matched {
		return value, nil
	}
	if err := write(string(text[end:])); err != nil {
		return "", err
	}
	return out.String(), nil
}
