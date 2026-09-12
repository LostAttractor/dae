package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/outbound/protocol/direct"
)

func TestNewControlPlaneHonorsCanceledContext(t *testing.T) {
	previousDirect, previousBootstrap := direct.Direct, direct.Bootstrap
	t.Cleanup(func() { direct.Direct, direct.Bootstrap = previousDirect, previousBootstrap })
	for name, bpf := range map[string]*control.BPFState{"startup": nil, "reload": {}} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := newControlPlane(ctx, bpf, &config.Config{}, nil, nil, nil)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("newControlPlane error = %v, want context cancellation", err)
			}
		})
	}
}

func TestNewControlPlaneRejectsEffectiveTproxyMark(t *testing.T) {
	conf := &config.Config{
		Global: config.Global{SoMarkFromDae: consts.TproxyMark | 0x42},
	}
	if _, err := newControlPlane(context.Background(), nil, conf, nil, nil, nil); err == nil {
		t.Fatal("newControlPlane accepted an effective mark containing TproxyMark")
	} else if !strings.Contains(err.Error(), "reserved tproxy mark") {
		t.Fatalf("newControlPlane returned unexpected error: %v", err)
	}
}
