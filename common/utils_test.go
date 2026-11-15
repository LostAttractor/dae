package common

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/internal/routingabi"
)

func TestValidateSoMarkFromDae(t *testing.T) {
	for _, mark := range []uint32{consts.TproxyMark, consts.TproxyMark | 0x1234, ^uint32(0), routingabi.DNS_REPLY_MARK} {
		if err := ValidateSoMarkFromDae(mark); err == nil {
			t.Errorf("ValidateSoMarkFromDae(%#x) accepted a reserved mark", mark)
		}
	}
	for _, mark := range []uint32{0, 0x100, 0x2023, routingabi.DNS_REPLY_MARK | 0x100} {
		if err := ValidateSoMarkFromDae(mark); err != nil {
			t.Errorf("ValidateSoMarkFromDae(%#x) = %v", mark, err)
		}
	}
}
