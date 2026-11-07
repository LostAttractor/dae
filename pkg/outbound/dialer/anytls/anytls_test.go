package anytls

import "testing"

func TestParseAnytlsURL(t *testing.T) {
	for _, tc := range []struct {
		link, name, sni string
		insecure        bool
	}{
		{"anytls://pw@example.com:443?sni=a.example&insecure=1#HK-1", "HK-1", "a.example", true},
		{"anytls://pw@example.com:443#HK-2", "HK-2", "example.com", false},
		{"anytls://pw@[2001:db8::1]:443/?insecure=1", "", "2001:db8::1", true},
	} {
		s, name, err := parseAnytlsURL(tc.link)
		if err != nil {
			t.Fatalf("%s: %v", tc.link, err)
		}
		if name != tc.name || s.Sni != tc.sni || s.Insecure != tc.insecure || s.Auth != "pw" {
			t.Fatalf("%s: name=%q sni=%q insecure=%v auth=%q", tc.link, name, s.Sni, s.Insecure, s.Auth)
		}
	}
}
