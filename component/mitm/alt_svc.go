// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/component/mitm/plugin"
	"golang.org/x/net/http/httpguts"
)

// Advertise only upstream HTTP/3 services that retain the intercepted
// authority and its scoped port. Alternative ports preserve the origin's
// authority in HTTP requests, which our destination-bound handler rejects.
// Never manufacture an advertisement for an upstream that did not send one.
func (h *Host) filterAltSvc(header http.Header, scheme string, flow plugin.Flow) {
	values := header.Values("Alt-Svc")
	header.Del("Alt-Svc")
	if scheme != "https" || h.Match(flow.Host, flow.Port) == HTTPBypass {
		return
	}
	var kept []string
	for _, value := range values {
		entries, valid := splitAltSvc(value)
		if !valid {
			continue
		}
		for _, entry := range entries {
			if entry == "clear" {
				// RFC 7838: clear invalidates all alternatives, including others
				// in the same response. It does not advertise a new service.
				header.Set("Alt-Svc", "clear")
				return
			}
			authority, params, valid := parseAltSvcH3(entry)
			if !valid {
				continue
			}
			host, portText, err := net.SplitHostPort(authority)
			port, portErr := strconv.ParseUint(portText, 10, 16)
			if err != nil || portErr != nil || port != uint64(flow.Port) || !altSvcDecimal(portText) {
				continue
			}
			if host != "" && !sameAuthority(authority, flow.Host, flow.Port, "https") {
				continue
			}
			kept = append(kept, `h3=":`+strconv.Itoa(int(flow.Port))+`"`+params)
		}
	}
	if len(kept) > 0 {
		header.Set("Alt-Svc", strings.Join(kept, ", "))
	}
}

// Commas inside quoted parameter values are not alternative delimiters.
func splitAltSvc(value string) ([]string, bool) {
	if !httpguts.ValidHeaderFieldValue(value) {
		return nil, false
	}
	var entries []string
	start, quoted, escaped := 0, false, false
	for i := range len(value) {
		char := value[i]
		if escaped {
			escaped = false
			continue
		}
		if quoted && char == '\\' {
			escaped = true
		} else if char == '"' {
			quoted = !quoted
		} else if char == ',' && !quoted {
			entries = append(entries, strings.Trim(value[start:i], " \t"))
			start = i + 1
		}
	}
	if quoted || escaped {
		return nil, false
	}
	return append(entries, strings.Trim(value[start:], " \t")), true
}

// Parse the RFC 7838 quoted authority and parameter grammar. Unknown parameters
// are validated then discarded; retain only ma and the defined persist=1 hint.
func parseAltSvcH3(value string) (authority, params string, ok bool) {
	s := altSvcScanner(value)
	if s.token() != "h3" || !s.take('=') {
		return "", "", false
	}
	authority, ok = s.quoted()
	if !ok {
		return "", "", false
	}
	seen := make(map[string]bool)
	var maxAge, persist string
	for {
		s = altSvcScanner(strings.TrimLeft(string(s), " \t"))
		if s == "" {
			break
		}
		if !s.take(';') {
			return "", "", false
		}
		s = altSvcScanner(strings.TrimLeft(string(s), " \t"))
		name := strings.ToLower(s.token())
		if name == "" || seen[name] || !s.take('=') {
			return "", "", false
		}
		seen[name] = true
		var parameter string
		if strings.HasPrefix(string(s), `"`) {
			parameter, ok = s.quoted()
		} else {
			parameter = s.token()
			ok = parameter != ""
		}
		if !ok {
			return "", "", false
		}
		switch name {
		case "ma":
			seconds, err := strconv.ParseUint(parameter, 10, 64)
			if err != nil || !altSvcDecimal(parameter) {
				return "", "", false
			}
			maxAge = "; ma=" + strconv.FormatUint(seconds, 10)
		case "persist":
			if parameter == "1" {
				persist = "; persist=1"
			}
		}
	}
	return authority, maxAge + persist, true
}

func altSvcDecimal(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

type altSvcScanner string

func (s *altSvcScanner) take(char byte) bool {
	if len(*s) == 0 || (*s)[0] != char {
		return false
	}
	*s = (*s)[1:]
	return true
}

func (s *altSvcScanner) token() string {
	i := 0
	for i < len(*s) && httpguts.IsTokenRune(rune((*s)[i])) {
		i++
	}
	value := string((*s)[:i])
	*s = (*s)[i:]
	return value
}

func (s *altSvcScanner) quoted() (string, bool) {
	if !s.take('"') {
		return "", false
	}
	var value strings.Builder
	for len(*s) > 0 {
		char := (*s)[0]
		*s = (*s)[1:]
		if char == '"' {
			return value.String(), true
		}
		if char == '\\' {
			if len(*s) == 0 {
				return "", false
			}
			char = (*s)[0]
			*s = (*s)[1:]
		}
		if char < ' ' && char != '\t' || char == 127 {
			return "", false
		}
		value.WriteByte(char)
	}
	return "", false
}
