// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// NormalizeOrigin validates and canonicalizes an exact HTTP(S) origin.
func NormalizeOrigin(value string) (string, error) {
	if strings.ContainsAny(value, "?#") {
		return "", fmt.Errorf("expected an exact HTTP(S) origin without userinfo, path, query or fragment")
	}
	u, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("expected an exact HTTP(S) origin without userinfo, path, query or fragment")
	}
	return NormalizeOriginURL(u)
}

// NormalizeOriginURL validates and canonicalizes a parsed HTTP(S) origin without a path.
func NormalizeOriginURL(u *url.URL) (string, error) {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("expected an exact HTTP(S) origin without userinfo, path, query or fragment")
	}
	host := strings.ToLower(u.Hostname())
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || ip.Is6() != strings.HasPrefix(u.Host, "[") {
			return "", fmt.Errorf("invalid origin IP literal")
		}
		host = ip.String()
		if ip.Is6() {
			host = "[" + host + "]"
		}
	} else if strings.ContainsAny(host, "*:[]%\\") || strings.ContainsAny(u.Host, "[]") {
		return "", fmt.Errorf("invalid origin hostname")
	}
	port := u.Port()
	if port != "" || strings.HasSuffix(u.Host, ":") {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return "", fmt.Errorf("origin port must be between 1 and 65535")
		}
		port = strconv.Itoa(int(n))
		if u.Scheme == "http" && n == 80 || u.Scheme == "https" && n == 443 {
			port = ""
		}
	}
	if port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host, nil
}
