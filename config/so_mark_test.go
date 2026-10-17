package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestSoMarkFromDaePreservesExplicitZero(t *testing.T) {
	conf := parseConfig(t, `
global { so_mark_from_dae: 0 }
routing { fallback: direct }
`)
	if conf.Global.SoMarkFromDae != 0 {
		t.Fatal("explicit zero was not preserved")
	}
}

func TestSoMarkFromDaeDefaults(t *testing.T) {
	conf := parseConfig(t, `
global {}
routing { fallback: direct }
`)
	if conf.Global.SoMarkFromDae != 0x100 {
		t.Fatal("omitted socket mark did not use the default")
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
