// SPDX-License-Identifier: AGPL-3.0-only

// Package proxylink handles the textual conventions shared by proxy links,
// subscriptions and named upstreams. It has no runtime or daemon dependencies.
package proxylink

import (
	"encoding/base64"
	"strings"
)

// SplitTag separates a name prefix without treating a URL scheme as a name.
func SplitTag(link string) (tag, value string) {
	before, after, found := strings.Cut(link, ":")
	if !found || strings.HasPrefix(after, "//") {
		return "", link
	}
	return before, after
}

// DecodeBase64 accepts omitted padding and preserves trimmed input on error.
func DecodeBase64(s string) (string, error)    { return decode(s, base64.StdEncoding) }
func DecodeBase64URL(s string) (string, error) { return decode(s, base64.URLEncoding) }

func decode(s string, encoding *base64.Encoding) (string, error) {
	s = strings.TrimSpace(s)
	original := s
	if padding := len(s) % 4; padding != 0 {
		s += strings.Repeat("=", 4-padding)
	}
	raw, err := encoding.DecodeString(s)
	if err != nil {
		return original, err
	}
	return string(raw), nil
}
