package netproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	quic "github.com/daeuniverse/quic-go"
	"golang.org/x/net/http2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFailuresPreserveAtomicProtocolEvidence(t *testing.T) {
	for _, tt := range []struct {
		name   string
		err    error
		scope  FailureScope
		layer  FailureLayer
		reason FailureReason
	}{
		{"quic transport", &quic.TransportError{ErrorCode: 1}, ScopeSharedResource, LayerQUIC, ReasonProtocol},
		{"quic application", &quic.ApplicationError{ErrorCode: 42}, ScopeSharedResource, LayerQUIC, ReasonProtocol},
		{"quic connection timeout", &quic.IdleTimeoutError{}, ScopeSharedResource, LayerQUIC, ReasonDeadline},
		{"quic stream", &quic.StreamError{ErrorCode: 42}, ScopeStream, LayerQUIC, ReasonReset},
		{"quic capacity value", quic.StreamLimitReachedError{}, ScopeOperation, LayerQUIC, ReasonCapacity},
		{"h2 stream", http2.StreamError{StreamID: 1, Code: http2.ErrCodeCancel}, ScopeStream, LayerH2, ReasonReset},
		{"h2 connection", http2.ConnectionError(http2.ErrCodeProtocol), ScopeSharedResource, LayerH2, ReasonProtocol},
		{"grpc unavailable", status.Error(codes.Unavailable, "peer lost"), ScopeStream, LayerGRPC, ReasonRejected},
		{"deadline", os.ErrDeadlineExceeded, ScopeOperation, LayerUnknown, ReasonDeadline},
	} {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := fmt.Errorf("adapter: %w", tt.err)
			failures := Failures(wrapped)
			if len(failures) != 1 {
				t.Fatalf("got %d failure leaves, want one: %v", len(failures), failures)
			}
			f := failures[0]
			if f.Scope != tt.scope || f.Layer != tt.layer || f.Reason != tt.reason {
				t.Fatalf("classification = %+v", f)
			}
			switch tt.err.(type) {
			case *quic.StreamError, *quic.TransportError, *quic.ApplicationError:
				if f.Origin != OriginLocalProtocol {
					t.Fatalf("local protocol error attributed to peer: %+v", f)
				}
			}
			if !errors.Is(f.Cause, tt.err) {
				t.Fatal("original protocol evidence lost")
			}
		})
	}
}

func TestFailuresJoinOrderAndOuterMetadata(t *testing.T) {
	fatal := &quic.TransportError{ErrorCode: 1}
	ref := NewResourceRef()
	for _, joined := range []error{errors.Join(context.DeadlineExceeded, fatal), errors.Join(fatal, context.DeadlineExceeded)} {
		failure := WrapFailure(fmt.Errorf("relay: %w", joined), Failure{Resource: ref, Phase: OpWrite})
		failures := Failures(failure)
		if len(failures) != 2 {
			t.Fatalf("got %d leaves", len(failures))
		}
		scopes := map[FailureScope]int{}
		for _, f := range failures {
			scopes[f.Scope]++
			if f.Resource != ref || f.Phase != OpWrite {
				t.Fatalf("lost outer metadata: %+v", f)
			}
		}
		if scopes[ScopeOperation] != 1 || scopes[ScopeSharedResource] != 1 {
			t.Fatalf("scope counts = %v", scopes)
		}
	}
}

func TestClosedSentinelDoesNotProveLocalCleanup(t *testing.T) {
	f := ClassifyFailure(net.ErrClosed)
	if f.Origin == OriginLocalCleanup || f.Scope != ScopeUnknown {
		t.Fatalf("invented close attribution: %+v", f)
	}
	fatal := &quic.ApplicationError{ErrorCode: 3}
	if !errors.Is(fatal, net.ErrClosed) {
		t.Fatal("test requires compatibility closed sentinel")
	}
	f = ClassifyFailure(fatal)
	if f.Scope != ScopeSharedResource || f.Origin == OriginLocalCleanup {
		t.Fatalf("lost fatal cause: %+v", f)
	}
}
