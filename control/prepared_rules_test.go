// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/config"
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
	rules, err := prepareRoutingRules(t.Context(), &conf.Routing, []string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := rules.enableFlowRules(t.Context(), config.Rules{}, []string{dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := compileTestRouting(rules, map[string]uint8{"direct": 0}, nil, nil); err != nil {
		t.Fatal(err)
	}
}
