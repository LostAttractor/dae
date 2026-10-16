// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestPrepareRulesWithoutGeodata(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_ASSET", dir)
	// Invalid files make any accidental eager decode fail even when the host
	// happens to have usable geodata installed in a default search directory.
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("invalid geodata"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	conf := parseStructuredTestConfig(t, `
dip(192.168.0.0/16) -> direct
domain(suffix:example.com) -> direct
fallback: direct`)
	prepared, err := PrepareRules(t.Context(), &conf.Routing, []string{dir})
	if err != nil {
		t.Fatal(err)
	}
	rules := prepared.copy()
	if _, err := rules.compileRouting(map[string]uint8{"direct": 0}, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareRulesReportsInvalidGeodata(t *testing.T) {
	// A valid list and country-code prefix select the fast decoder, but the
	// nested CIDR/domain message is truncated. A text response uses the fallback.
	entry := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "private")
	entry = protowire.AppendBytes(protowire.AppendTag(entry, 2, protowire.BytesType), []byte{0xff})
	invalidEntry := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), entry)
	for _, dataset := range []struct {
		name, file, predicate string
	}{
		{"GeoIP", "geoip.dat", "dip(geoip:private)"},
		{"GeoSite", "geosite.dat", "domain(geosite:private)"},
	} {
		for _, fixture := range []struct {
			name string
			data []byte
		}{
			{"failed download", []byte("Bad Gateway")},
			{"invalid entry", invalidEntry},
		} {
			t.Run(dataset.name+"/"+fixture.name, func(t *testing.T) {
				dir := t.TempDir()
				t.Setenv("DAE_LOCATION_ASSET", dir)
				path := filepath.Join(dir, dataset.file)
				if err := os.WriteFile(path, fixture.data, 0o600); err != nil {
					t.Fatal(err)
				}
				conf := parseStructuredTestConfig(t, `rule_set {
 direct {
  client(direct) -> direct
  interface(direct) -> direct
  `+dataset.predicate+` -> direct
 }
}
use: direct
fallback: direct`)
				_, err := PrepareRules(t.Context(), &conf.Routing, []string{dir})
				if !errors.Is(err, proto.Error) {
					t.Fatalf("PrepareRules error = %v, want wrapped protobuf error", err)
				}
				for _, want := range []string{
					`prepare routing block "direct"`, dataset.name, `"private"`, path,
					"invalid protobuf data", "file format", "download integrity",
				} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("PrepareRules error = %v, want context %q", err, want)
					}
				}
			})
		}
	}
}
