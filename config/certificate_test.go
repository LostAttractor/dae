// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestCertificateConfiguration(t *testing.T) {
	for _, body := range []string{"", "certificate {}", "certificate { ca_cert: 'local.pem' ca_key: 'local.key' }"} {
		conf := parseConfig(t, "global {}\n"+body+"\nrouting { fallback: direct }")
		encoded, err := conf.Marshal(2)
		if err != nil {
			t.Fatal(err)
		}
		if got := parseConfig(t, string(encoded)); got.Certificate != conf.Certificate {
			t.Fatal("certificate selection changed during round trip")
		}
	}
	for _, body := range []string{"certificate { ca_cert: cert }", "certificate { ca_key: key }", "certificate { unknown: value }", "mitm { ca_cert: cert ca_key: key }"} {
		sections, err := config_parser.Parse("global {}\n" + body + "\nrouting { fallback: direct }")
		if err == nil {
			_, err = New(sections)
		}
		if err == nil {
			t.Fatalf("accepted invalid certificate settings: %s", body)
		}
	}
}
