package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestSoMarkFromDaeTracksExplicitConfiguration(t *testing.T) {
	conf := parseConfig(t, `
global { so_mark_from_dae: 0 }
routing { fallback: direct }
`)
	if !conf.Global.SoMarkFromDaeSet {
		t.Fatal("SoMarkFromDaeSet = false, want true")
	}
}

func TestSoMarkFromDaeTracksOmittedConfiguration(t *testing.T) {
	conf := parseConfig(t, `
global {}
routing { fallback: direct }
`)
	if conf.Global.SoMarkFromDaeSet {
		t.Fatal("SoMarkFromDaeSet = true, want false")
	}
}

func TestSoMarkFromDaeRejectsTproxyMark(t *testing.T) {
	for _, mark := range []uint32{consts.TproxyMark, consts.TproxyMark | 0x21} {
		sections, err := config_parser.Parse(fmt.Sprintf(`
global { so_mark_from_dae: %#x }
routing { fallback: direct }
`, mark))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = New(sections); err == nil {
			t.Errorf("so_mark_from_dae %#x was accepted", mark)
		} else if !strings.Contains(err.Error(), "reserved tproxy mark") {
			t.Errorf("unexpected error for so_mark_from_dae %#x: %v", mark, err)
		}
	}
}
