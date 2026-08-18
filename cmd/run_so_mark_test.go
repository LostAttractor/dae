package cmd

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
)

func TestConfigureDaemonResolverValidation(t *testing.T) {
	invalid := &config.Global{SoMarkFromDae: consts.TproxyMark | 1}
	if err := configureDaemonResolver(invalid); err == nil {
		t.Fatal("configureDaemonResolver accepted TproxyMark")
	} else if !strings.Contains(err.Error(), "reserved tproxy mark") {
		t.Fatalf("configureDaemonResolver returned unexpected error: %v", err)
	}
}

func TestNewControlPlaneRejectsEffectiveTproxyMark(t *testing.T) {
	conf := &config.Config{
		Global: config.Global{SoMarkFromDae: consts.TproxyMark | 0x42},
	}
	if _, err := newControlPlane(nil, conf, nil); err == nil {
		t.Fatal("newControlPlane accepted an effective mark containing TproxyMark")
	} else if !strings.Contains(err.Error(), "reserved tproxy mark") {
		t.Fatalf("newControlPlane returned unexpected error: %v", err)
	}
}
