// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"encoding/base64"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/dlclark/regexp2"
	"golang.org/x/net/http/httpguts"
)

// MapLocal returns a preloaded, immutable response without contacting upstream.
type MapLocal struct {
	Pattern, DataType, Data string
	Status                  int
	Header                  http.Header
	Body                    []byte
	pattern                 *regexp2.Regexp
}

func (r MapLocal) Match(rawURL string) bool { return matchPattern(r.pattern, rawURL) }

func parseMapLocal(line string, warnings *[]string) (*MapLocal, error) {
	end := strings.IndexAny(line, " \t")
	if end < 0 {
		return nil, fmt.Errorf("Map Local requires URL pattern and parameters")
	}
	params, err := mapLocalParameters(line[end:])
	if err != nil {
		return nil, err
	}
	r := &MapLocal{Pattern: line[:end], DataType: "file", Status: http.StatusOK, Header: make(http.Header)}
	if r.pattern, err = compilePattern(r.Pattern); err != nil {
		return nil, err
	}
	for key, value := range params {
		switch key {
		case "data-type":
			r.DataType = value
		case "data":
			r.Data = value
		case "status-code":
			r.Status, err = strconv.Atoi(value)
			if err != nil || r.Status < 200 || r.Status > 999 {
				return nil, fmt.Errorf("Map Local status-code must be between 200 and 999")
			}
		case "header":
			if !strings.Contains(value, ":") && value != "" {
				decoded, err := base64.StdEncoding.DecodeString(value)
				if err != nil {
					return nil, fmt.Errorf("Map Local header base64: %w", err)
				}
				value = strings.ReplaceAll(strings.ReplaceAll(string(decoded), "\r\n", "\n"), "\n", "|")
			}
			for entry := range strings.SplitSeq(value, "|") {
				if strings.TrimSpace(entry) == "" {
					continue
				}
				key, val, ok := strings.Cut(entry, ":")
				key, val = strings.TrimSpace(key), strings.TrimSpace(val)
				if !ok || !httpguts.ValidHeaderFieldName(key) || !httpguts.ValidHeaderFieldValue(val) {
					return nil, fmt.Errorf("invalid Map Local response header")
				}
				if strings.EqualFold(key, "Content-Length") || strings.EqualFold(key, "Transfer-Encoding") {
					return nil, fmt.Errorf("Map Local cannot set message framing via %s", key)
				}
				r.Header.Add(key, val)
			}
		default:
			*warnings = append(*warnings, fmt.Sprintf("Map Local: unsupported parameter %q is ignored", key))
		}
	}
	contentType := "application/octet-stream"
	switch r.DataType {
	case "text":
		r.Body = []byte(r.Data)
		contentType = "text/plain"
	case "base64":
		r.Body, err = base64.StdEncoding.DecodeString(r.Data)
		if err != nil {
			return nil, fmt.Errorf("Map Local data base64: %w", err)
		}
	case "tiny-gif":
		r.Body, _ = base64.StdEncoding.DecodeString("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
		contentType = "image/gif"
	case "file":
		if r.Data == "" {
			return nil, fmt.Errorf("Map Local file requires data path")
		}
		dataPath := r.Data
		if location, err := url.Parse(r.Data); err == nil && location.Scheme != "" {
			dataPath = location.Path
			if location.Opaque != "" {
				dataPath, err = url.PathUnescape(location.Opaque)
				if err != nil {
					return nil, fmt.Errorf("Map Local file path: %w", err)
				}
			}
		}
		if detected := mime.TypeByExtension(filepath.Ext(dataPath)); detected != "" {
			contentType = detected
		}
	default:
		*warnings = append(*warnings, fmt.Sprintf("Map Local: unsupported data-type %q; rule is ignored", r.DataType))
		return nil, nil
	}
	if r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r, nil
}

// Surge accepts nested, unescaped quotes in JSON data="{"key":"value"}".
// A quoted value ends at a quote followed by whitespace and another key= (or EOF).
func mapLocalParameters(source string) (map[string]string, error) {
	params := make(map[string]string)
	for strings.TrimSpace(source) != "" {
		source = strings.TrimSpace(source)
		key, rest, ok := strings.Cut(source, "=")
		if !ok || !parameterKey(key) {
			return nil, fmt.Errorf("invalid Map Local parameter %q", source)
		}
		var value string
		if len(rest) > 0 && (rest[0] == '"' || rest[0] == '\'') {
			end := -1
			for i := 1; i < len(rest); i++ {
				if rest[i] == '\\' {
					i++
					continue
				}
				if rest[i] != rest[0] {
					continue
				}
				next := rest[i+1:]
				if next == "" || strings.TrimSpace(next) == "" || (next[0] == ' ' || next[0] == '\t') && nextParameter(strings.TrimSpace(next)) {
					end = i
					break
				}
			}
			if end < 0 {
				return nil, fmt.Errorf("unterminated Map Local parameter %q", key)
			}
			value = rest[1:end]
			if unquoted, err := strconv.Unquote(rest[:end+1]); err == nil {
				value = unquoted
			}
			source = rest[end+1:]
		} else if end := strings.IndexAny(rest, " \t"); end >= 0 {
			value, source = rest[:end], rest[end:]
		} else {
			value, source = rest, ""
		}
		if _, exists := params[key]; exists {
			return nil, fmt.Errorf("duplicate Map Local parameter %q", key)
		}
		params[key] = value
	}
	return params, nil
}

func (e *Engine) mapLocal(r *http.Request) (*http.Response, error) {
	for _, m := range e.options.Modules {
		for i, rule := range m.MapLocals {
			if !rule.Match(r.URL.String()) {
				continue
			}
			e.traceRequest(r, "map_local_match", "module", m.Name, "rule", i+1, "status", rule.Status)
			if int64(len(rule.Body)) > e.options.MaxBodySize {
				return nil, membuffer.ErrTooLarge
			}
			return syntheticResponse(r, rule.Status, rule.Header.Clone(), rule.Body), nil
		}
	}
	return nil, nil
}
