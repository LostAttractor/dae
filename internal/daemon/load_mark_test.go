package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
)

func TestNewControlPlaneHonorsCanceledContext(t *testing.T) {
	bpf := control.NewRuntime()
	t.Cleanup(func() { _ = bpf.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newControlPlane(ctx, bpf, &config.Config{}, nil, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("newControlPlane error = %v, want context cancellation", err)
	}
}

func TestNewControlPlaneRejectsInitializationReaderLifetime(t *testing.T) {
	recording, inputs := resource.WithInputRecording(t.Context())
	for _, ctx := range []context.Context{recording, resource.WithInputReplay(t.Context(), inputs)} {
		if _, err := newControlPlane(ctx, nil, nil, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "must not retain initialization inputs") {
			t.Fatalf("live constructor retained a recording/replay context: %v", err)
		}
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
