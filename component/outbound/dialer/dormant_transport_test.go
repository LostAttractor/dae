// SPDX-License-Identifier: AGPL-3.0-only

package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/netproxy"
)

type sleepingTestTransport struct{ closed atomic.Bool }

func (t *sleepingTestTransport) Close() error { t.closed.Store(true); return nil }
func (t *sleepingTestTransport) DialContext(context.Context, string, string) (net.Conn, error) {
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}
func (t *sleepingTestTransport) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}

func TestDormantTransportDrainsAndRecreates(t *testing.T) {
	var generations []*netproxy.Runtime
	factory := func() (*netproxy.Runtime, error) {
		transport := new(sleepingTestTransport)
		runtime := netproxy.NewRuntime(netproxy.Layer{Data: transport, Resources: []io.Closer{transport}})
		generations = append(generations, runtime)
		return runtime, nil
	}
	d, err := NewRecreatableDialer(factory, &GlobalOption{}, &Property{Name: t.Name()}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	conn, err := d.DialContext(t.Context(), "tcp", "target:80")
	if err != nil {
		t.Fatal(err)
	}
	d.SetCheckEnabled(false)
	if !d.session.Snapshot().Accepting {
		t.Fatal("live connection was retired by sleep")
	}
	_ = conn.Close()
	if d.session.Snapshot().Accepting {
		t.Fatal("idle transport remained accepting")
	}
	if err := generations[0].Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	firstReadiness := d.session.Snapshot().ReadinessVersion
	d.SetSelected(true)
	if err := d.session.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(generations) != 2 || !d.session.Snapshot().Accepting || d.session.Snapshot().ReadinessVersion <= firstReadiness {
		t.Fatal("wake did not establish a new physical generation")
	}
	d.SetSelected(false)
	if err := generations[1].Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	if d.RuntimeStatus().Degraded {
		t.Fatal("voluntary sleep counted as a failure")
	}
}

func TestDormantTransportPreservesReadinessAcrossGenerations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var children []*testSessionTransport
		d, err := NewRecreatableDialer(func() (*netproxy.Runtime, error) {
			child := newTestSessionTransport(netproxy.SessionConnected)
			children = append(children, child)
			return netproxy.NewRuntime(netproxy.Layer{Data: child, Sessions: []netproxy.Session{child}}), nil
		}, &GlobalOption{}, &Property{Name: t.Name()}, "")
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		before := d.session.Snapshot().ReadinessVersion
		d.SetCheckEnabled(false)
		d.SetSelected(true)
		if err := d.session.Connect(t.Context()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		current := d.session.Snapshot()
		if len(children) != 2 || !current.Accepting || current.ReadinessVersion <= before {
			t.Fatal("wake reused the retired generation's readiness")
		}
		// Readiness can change without changing State, Resource or Accepting.
		event := children[1].Snapshot()
		event.ReadinessVersion++
		children[1].state.Publish(event)
		synctest.Wait()
		if d.session.Snapshot().ReadinessVersion <= current.ReadinessVersion {
			t.Fatal("child readiness change was lost")
		}
		current = d.session.Snapshot()
		children[0].state.Transition(netproxy.SessionDisconnected, errors.New("retired child failed"))
		synctest.Wait()
		if got := d.session.Snapshot(); got.Seq != current.Seq || !got.Accepting {
			t.Fatal("retired child changed the active generation")
		}
	})
}

func TestSelectionProofHoldsTransportUntilCommit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, err := NewRecreatableDialer(func() (*netproxy.Runtime, error) {
			return netproxy.NewRuntime(netproxy.Layer{Data: new(sleepingTestTransport)}), nil
		}, &GlobalOption{}, &Property{Name: t.Name()}, "")
		if err != nil {
			t.Fatal(err)
		}
		d.SetCheckEnabled(false)
		checker := newConnectivityChecker(d.pathRuntime, func(context.Context, *common.NetworkType) (bool, error) { return true, nil })
		start := make(chan struct{})
		close(start)
		var worker sync.WaitGroup
		worker.Go(func() { checker.run(start) })
		defer func() { _ = d.Close(); worker.Wait() }()
		proof, err := d.Check(t.Context(), common.NetworkTCP4, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer proof.Release()
		// Let the worker finish and dispatch all idle notifications before the
		// group consumes its result. No connection or periodic check holds it.
		synctest.Wait()
		if !d.ProofValid(proof) {
			t.Fatal("idle transport retired before selection consumed its proof")
		}
		retained, ok := d.RetainProof(proof)
		if !ok {
			t.Fatal("could not retain background result")
		}
		defer retained.Release()
		proof.Release()
		synctest.Wait()
		if !d.ProofValid(retained) {
			t.Fatal("retained background result lost its Session")
		}
		retained.Release()
		synctest.Wait()
		if d.session.Snapshot().Accepting {
			t.Fatal("released proof retained an unused session")
		}
	})
}
