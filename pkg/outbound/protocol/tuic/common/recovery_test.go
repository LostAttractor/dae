package common

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/quic-go"
)

func TestRecoveryQUICFailureScope(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		scope netproxy.FailureScope
		fatal bool
	}{
		{"stream reset", &quic.StreamError{StreamID: 4, Remote: true, ErrorCode: 2}, netproxy.ScopeStream, false},
		{"transport", &quic.TransportError{Remote: true, ErrorCode: quic.ProtocolViolation}, netproxy.ScopeSharedResource, true},
		{"idle timeout", &quic.IdleTimeoutError{}, netproxy.ScopeSharedResource, true},
		{"capacity", quic.StreamLimitReachedError{}, netproxy.ScopeOperation, false},
		{"read deadline", os.ErrDeadlineExceeded, netproxy.ScopeOperation, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref := netproxy.NewResourceRef()
			parent := netproxy.NewLease(ref)
			first, second := parent.NewStream(), parent.NewStream()
			fatal := false
			err := WrapQUICError(fmt.Errorf("wrapped: %w", tc.err), ref, first, netproxy.OpRead, func(cause error) { fatal = true; parent.Invalidate(cause) })
			failure := netproxy.ClassifyFailure(err)
			if failure.Scope != tc.scope || failure.Resource != ref || fatal != tc.fatal || !errors.Is(err, tc.err) {
				t.Fatalf("failure=%+v fatal=%v", failure, fatal)
			}
			if second.Valid() == tc.fatal {
				t.Fatalf("sibling stream validity=%v", second.Valid())
			}
			if !tc.fatal && tc.scope == netproxy.ScopeStream && first.Valid() {
				t.Fatal("reset stream lease remains valid")
			}
		})
	}
}

func TestRecoveryPoolPreservesHealthyMembersAndRejectsStaleFailures(t *testing.T) {
	p := NewQUICPoolState()
	a, b := p.NewResource(), p.NewResource()
	p.Ready(a)
	p.Ready(b)
	healthy := p.Snapshot()
	firstCause := errors.New("first connection reset")
	p.Failed(a, firstCause)
	if event := p.Snapshot(); event.State != netproxy.SessionConnected || !event.Accepting || event.UsableCapacity != 1 || !errors.Is(event.Cause, firstCause) {
		t.Fatalf("healthy sibling lost: %+v", event)
	}
	if event := p.Snapshot(); event.ReadinessVersion != healthy.ReadinessVersion || !event.RecoveryRequired {
		t.Fatalf("pool loss invalidated healthy proof or omitted replenishment: %+v", event)
	}
	p.Failed(b, errors.New("second connection reset"))
	if event := p.Snapshot(); event.State != netproxy.SessionDisconnected || event.Accepting {
		t.Fatalf("failed pool state: %+v", event)
	}
	p.Remove(a)
	c := p.NewResource()
	p.Ready(c)
	before := p.Snapshot()
	p.Failed(a, errors.New("late old resource error"))
	if after := p.Snapshot(); after.Seq != before.Seq || after.State != netproxy.SessionConnected {
		t.Fatalf("stale resource changed replacement: %+v", after)
	}
	p.Close()
	p.Ready(c)
	if p.Snapshot().State != netproxy.SessionClosed {
		t.Fatal("closed pool resurrected")
	}
}

func TestRecoveryCleanupDoesNotHideRemoteReset(t *testing.T) {
	for _, remote := range []bool{false, true} {
		parent := netproxy.NewLease(netproxy.NewResourceRef())
		stream := parent.NewStream()
		stream.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Origin: netproxy.OriginLocalCleanup, Scope: netproxy.ScopeStream}))
		err := WrapQUICError(&quic.StreamError{Remote: remote, StreamID: 4, ErrorCode: 7}, parent.Resource(), stream, netproxy.OpRead, nil)
		failure := netproxy.ClassifyFailure(err)
		want := netproxy.OriginLocalCleanup
		if remote {
			want = netproxy.OriginPeer
		}
		if failure.Origin != want {
			t.Fatalf("remote=%v origin=%v want=%v", remote, failure.Origin, want)
		}
	}
}

func TestRecoveryJoinedStreamAndConnectionFailurePreserveBoth(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		parent := netproxy.NewLease(netproxy.NewResourceRef())
		stream := parent.NewStream()
		reset := &quic.StreamError{Remote: true, ErrorCode: 7}
		fatal := &quic.TransportError{Remote: true, ErrorCode: 1}
		causes := []error{reset, fatal}
		if reverse {
			causes[0], causes[1] = causes[1], causes[0]
		}
		invalidations := 0
		err := WrapQUICError(errors.Join(causes...), parent.Resource(), stream, netproxy.OpRead, func(err error) { invalidations++; parent.Invalidate(err) })
		if len(netproxy.Failures(err)) != 2 || !errors.Is(err, reset) || !errors.Is(err, fatal) || invalidations != 1 || parent.Valid() {
			t.Fatalf("joined failure lost resource scope: %v invalidations=%d", err, invalidations)
		}
	}
}

func TestRecoveryWriteEOFRemainsFailure(t *testing.T) {
	err := WrapQUICError(io.EOF, netproxy.NewResourceRef(), nil, netproxy.OpWrite, nil)
	if err == io.EOF || !errors.Is(err, io.EOF) || netproxy.ClassifyFailure(err).Phase != netproxy.OpWrite {
		t.Fatalf("writer EOF lost failure provenance: %v", err)
	}
}

func TestRecoveryRetainsUnderlyingTCPFailureLayer(t *testing.T) {
	cause := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	err := WrapQUICError(cause, netproxy.NewResourceRef(), nil, netproxy.OpRead, nil)
	if failure := netproxy.ClassifyFailure(err); failure.Layer != netproxy.LayerTCP || !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("TCP dependency failure relabeled as QUIC: %+v", failure)
	}
}
