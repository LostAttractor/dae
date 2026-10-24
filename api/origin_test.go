// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"net/url"
	"testing"
)

func TestNormalizeOrigin(t *testing.T) {
	for _, test := range []struct{ value, want string }{
		{"https://WEB.Example", "https://web.example"},
		{"HTTPS://WEB.Example:443", "https://web.example"},
		{"http://WEB.Example:80", "http://web.example"},
		{"https://WEB.Example:00443", "https://web.example"},
		{"https://WEB.Example:08443", "https://web.example:8443"},
		{"http://localhost:65535", "http://localhost:65535"},
		{"https://192.0.2.1:443", "https://192.0.2.1"},
		{"https://[2001:0DB8:0:0:0:0:0:1]:443", "https://[2001:db8::1]"},
		{"http://[::1]:9080", "http://[::1]:9080"},
		{"https://[::ffff:192.0.2.1]", "https://[::ffff:192.0.2.1]"},
	} {
		t.Run(test.value, func(t *testing.T) {
			got, err := NormalizeOrigin(test.value)
			if err != nil || got != test.want {
				t.Fatalf("NormalizeOrigin() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
	for _, value := range []string{
		"", "null", "*", "//web.example", "ftp://web.example", "https:", "https:///", "https://:443",
		"https://user@web.example", "https://user:password@web.example", "https://web.example/", "https://web.example/path",
		"https://web.example?", "https://web.example?query", "https://web.example#", "https://web.example#fragment",
		"https://*.example", "https://web.example:", "https://web.example:0", "https://web.example:65536", "https://web.example:invalid",
		"https://web.example:80:90", "https://[not-an-ip]", "https://[192.0.2.1]", "https://[::1", "https://::1",
		"https://[fe80::1%25eth0]", "https://web.example\\path", " https://web.example", "https://web.example\n",
	} {
		t.Run(value, func(t *testing.T) {
			if got, err := NormalizeOrigin(value); err == nil {
				t.Fatalf("invalid origin normalized to %q", got)
			}
		})
	}
	if _, err := NormalizeOriginURL(nil); err == nil {
		t.Fatal("nil URL accepted")
	}
	u, err := url.Parse("https://WEB.Example:443")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := NormalizeOriginURL(u); err != nil || got != "https://web.example" {
		t.Fatalf("NormalizeOriginURL() = %q, %v", got, err)
	}
}
