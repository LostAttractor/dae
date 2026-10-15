package hysteria2

import (
	"errors"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
)

func TestUnsupportedObfuscationIsNotSilentlyDisabled(t *testing.T) {
	for _, query := range []string{"obfs=salamander&obfs-password=secret", "obfs-password=secret"} {
		if _, err := ParseHysteria2URL("hysteria2://password@proxy.example:443?" + query); !errors.Is(err, dialer.InvalidParameterErr) {
			t.Fatalf("unsupported encryption configuration accepted: %v", err)
		}
	}
}
