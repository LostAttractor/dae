package common

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

func TestEffectiveSoMarkFromDae(t *testing.T) {
	if got := EffectiveSoMarkFromDae(0); got != InternalSoMarkFromDae {
		t.Fatalf("EffectiveSoMarkFromDae(0) = %#x, want %#x", got, InternalSoMarkFromDae)
	}
	const configured = uint32(0x2023)
	if got := EffectiveSoMarkFromDae(configured); got != configured {
		t.Fatalf("EffectiveSoMarkFromDae(%#x) = %#x, want %#x", configured, got, configured)
	}
}

func TestResolveSoMarkFromDae(t *testing.T) {
	if got, auto := ResolveSoMarkFromDae(0, false); got != InternalSoMarkFromDae || !auto {
		t.Fatalf("ResolveSoMarkFromDae(0, false) = (%#x, %v), want (%#x, true)", got, auto, InternalSoMarkFromDae)
	}
	if got, auto := ResolveSoMarkFromDae(0, true); got != InternalSoMarkFromDae || auto {
		t.Fatalf("ResolveSoMarkFromDae(0, true) = (%#x, %v), want (%#x, false)", got, auto, InternalSoMarkFromDae)
	}
}

func TestValidateSoMarkFromDae(t *testing.T) {
	for _, mark := range []uint32{consts.TproxyMark, consts.TproxyMark | 0x1234, ^uint32(0)} {
		if err := ValidateSoMarkFromDae(mark); err == nil {
			t.Errorf("ValidateSoMarkFromDae(%#x) accepted a reserved tproxy mark", mark)
		}
	}
	for _, mark := range []uint32{0, InternalSoMarkFromDae, 0x2023} {
		if err := ValidateSoMarkFromDae(mark); err != nil {
			t.Errorf("ValidateSoMarkFromDae(%#x) = %v", mark, err)
		}
	}
}
