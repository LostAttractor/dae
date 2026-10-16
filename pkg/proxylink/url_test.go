// SPDX-License-Identifier: AGPL-3.0-only

package proxylink

import "testing"

func TestPortUnionURL(t *testing.T) {
	for _, test := range []struct{ link, host string }{
		{"hy2://secret@proxy.example:443,5000-5010?sni=example.test#name", "proxy.example:443,5000-5010"},
		{"HyStErIa2://user:p%40ss@[2001:db8::1]:1000-2000,443/path?x=a:b#c:d", "[2001:db8::1]:1000-2000,443"},
		{"hy2://secret@[fe80::1%25eth0]:443-445", "[fe80::1%eth0]:443-445"},
		{"hy2://user:1000-2000@proxy.example", "proxy.example"},
		{"hy2://secret@proxy.example:443?ports=1-3", "proxy.example:443"},
		{"https://user:1-3@proxy.example:443/path:1-2", "proxy.example:443"},
	} {
		t.Run(test.link, func(t *testing.T) {
			u, err := ParseURL(test.link)
			if err != nil || u.Host != test.host {
				t.Fatalf("parse = %v, %v; want host %s", u, err, test.host)
			}
			roundTrip, err := ParseURL(u.String())
			if err != nil || roundTrip.Host != u.Host || roundTrip.User.String() != u.User.String() || roundTrip.RawQuery != u.RawQuery || roundTrip.Fragment != u.Fragment {
				t.Fatalf("port union changed URL components: %v, %v", roundTrip, err)
			}
		})
	}
	for _, link := range []string{
		"https://proxy.example:1-3", "hy2://user%zz@proxy.example:1-3",
		"hy2://[::1:1-3", "hy2://[::1]suffix:1-3", "hy2://proxy.example:abc-3",
		"hy2://proxy.example:1-3/%zz", "hy2://proxy.example:1-3#%zz",
	} {
		if u, err := ParseURL(link); err == nil {
			t.Fatalf("accepted malformed URL %q: %v", link, u)
		}
	}
}
