// SPDX-License-Identifier: AGPL-3.0-only

package proxylink

import (
	"net/url"
	"strings"
)

// ParseURL delegates URL syntax to net/url. Hysteria2 alone permits a comma-
// separated port union in the authority; remove that suffix during parsing,
// then restore it on the parsed host. Port-union validation belongs to udphop.
func ParseURL(link string) (*url.URL, error) {
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok || !strings.EqualFold(scheme, "hysteria2") && !strings.EqualFold(scheme, "hy2") {
		return url.Parse(link)
	}
	authorityEnd := strings.IndexAny(rest, "/?#")
	if authorityEnd < 0 {
		authorityEnd = len(rest)
	}
	authority, suffix := rest[:authorityEnd], rest[authorityEnd:]
	host, ports, ok := strings.CutLast(authority, ":")
	if !ok || !strings.ContainsAny(ports, "-,") {
		return url.Parse(link)
	}
	for _, c := range ports {
		if (c < '0' || c > '9') && c != '-' && c != ',' {
			return url.Parse(link)
		}
	}
	// A numeric port keeps authority/IPv6 validation intact and cannot appear
	// in query, path, fragment or userinfo, which the standard parser checks.
	u, err := url.Parse(scheme + "://" + host + ":0" + suffix)
	if err != nil {
		return nil, err
	}
	u.Host = strings.TrimSuffix(u.Host, ":0") + ":" + ports
	return u, nil
}
