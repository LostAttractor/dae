// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/plugin"
)

type constructionTestPlugin struct {
	controlTestPlugin
	closed   atomic.Int32
	closeErr error
}

func (p *constructionTestPlugin) Close() error {
	p.closed.Add(1)
	return p.closeErr
}

func TestControlPlaneValidationPreservesPreparation(t *testing.T) {
	conf := outboundUsageConfig(t, "global {}\nrouting { fallback: direct }")
	conf.Global.RerouteMode = consts.RerouteMode("invalid")
	bpf := &BPFState{}
	preparation := &ControlPlanePreparation{bpf: bpf}
	store := newControlPlaneTestBuilder(t).withSettings().build().settings
	if plane, err := NewControlPlane(t.Context(), preparation, nil, conf, store, nil); err == nil || plane != nil {
		t.Fatalf("invalid configuration constructed plane: %v %v", plane, err)
	}
	if preparation.bpf != bpf {
		t.Fatal("configuration validation consumed prepared kernel resources")
	}
}

func TestControlPlaneConstructionFailureClosesOwnedHost(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "plugin target failure"
		if canceled {
			name = "startup cancellation"
		}
		t.Run(name, func(t *testing.T) {
			conf := outboundUsageConfig(t, "global {}\nrouting { fallback: direct }")
			runtime := NewRuntime()
			t.Cleanup(func() { _ = runtime.Close() })
			interfaces, err := runtime.Interfaces()
			if err != nil {
				t.Fatal(err)
			}
			preparation := &ControlPlanePreparation{
				bpf:   &BPFState{bpfObjects: new(bpfObjects), Runtime: runtime},
				rules: preparedRules{routing: &conf.Routing}, isReload: true,
			}
			closeErr := errors.New("plugin cleanup failed")
			extension := &constructionTestPlugin{closeErr: closeErr}
			if !canceled {
				extension.plan = plugin.Plan{RequiredOutbounds: []string{"missing-target"}}
			}
			host := controlTestHost(t, extension, nil)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			store := newControlPlaneTestBuilder(t).withSettings().build().settings
			plane, err := NewControlPlane(ctx, preparation, nil, conf, store, func(*http.Client) (PreparedMITM, error) {
				if canceled {
					cancel()
				}
				return PreparedMITM{Host: host, plan: host.Plan()}, nil
			})
			if plane != nil || !errors.Is(err, closeErr) || extension.closed.Load() != 1 {
				t.Fatalf("partial candidate leaked ownership or cleanup error: plane=%v err=%v closed=%d", plane, err, extension.closed.Load())
			}
			if canceled && !errors.Is(err, net.ErrClosed) || !canceled && !strings.Contains(err.Error(), "missing-target") {
				t.Fatalf("construction error lost: %v", err)
			}
			if preparation.bpf != nil {
				t.Fatal("failed candidate retained transferred preparation")
			}
			shared, err := runtime.Interfaces()
			if err != nil || shared != interfaces {
				t.Fatalf("candidate failure replaced shared interface source: %v", err)
			}
			scope := shared.NewScope()
			defer scope.Close()
			if err := scope.RegisterSync("dae-absent-fixture", nil, nil, nil); err != nil {
				t.Fatalf("candidate failure closed shared source: %v", err)
			}
		})
	}
}
