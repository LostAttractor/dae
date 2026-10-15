package netproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"

	quic "github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	"golang.org/x/net/http2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type FailureScope string
type FailureLayer string
type Operation string
type FailureOrigin string
type FailureReason string
type RecoveryExecutor string

const (
	ScopeUnknown           FailureScope     = "unknown"
	ScopeOperation         FailureScope     = "operation"
	ScopeStream            FailureScope     = "stream"
	ScopeSharedResource    FailureScope     = "shared_resource"
	LayerUnknown           FailureLayer     = "unknown"
	LayerTCP               FailureLayer     = "tcp"
	LayerUDP               FailureLayer     = "udp"
	LayerTLS               FailureLayer     = "tls"
	LayerQUIC              FailureLayer     = "quic"
	LayerH2                FailureLayer     = "h2"
	LayerH3                FailureLayer     = "h3"
	LayerGRPC              FailureLayer     = "grpc"
	LayerProxy             FailureLayer     = "proxy"
	LayerSMUX              FailureLayer     = "smux"
	LayerAnyTLS            FailureLayer     = "anytls"
	OpDial                 Operation        = "dial"
	OpHandshake            Operation        = "handshake"
	OpOpenStream           Operation        = "open_stream"
	OpRead                 Operation        = "read"
	OpWrite                Operation        = "write"
	OpCloseWrite           Operation        = "close_write"
	OpClose                Operation        = "close"
	OriginUnknown          FailureOrigin    = "unknown"
	OriginCaller           FailureOrigin    = "caller"
	OriginTarget           FailureOrigin    = "target"
	OriginPeer             FailureOrigin    = "peer"
	OriginLocalProtocol    FailureOrigin    = "local_protocol"
	OriginLocalCleanup     FailureOrigin    = "local_cleanup"
	ReasonUnknown          FailureReason    = "unknown"
	ReasonReset            FailureReason    = "reset"
	ReasonRejected         FailureReason    = "rejected"
	ReasonCapacity         FailureReason    = "capacity"
	ReasonProtocol         FailureReason    = "protocol"
	ReasonDeadline         FailureReason    = "deadline"
	ReasonAuth             FailureReason    = "auth"
	ReasonClosed           FailureReason    = "closed"
	ReasonCanceled         FailureReason    = "canceled"
	RecoveryDaemon         RecoveryExecutor = "daemon"
	RecoveryLibraryManaged RecoveryExecutor = "library_managed"
)

// ResourceRef identifies an owner-controlled resource incarnation. Zero means
// unknown; a logical library channel must not impersonate a physical transport.
type ResourceRef struct {
	OwnerID    uint64 `json:"owner_id"`
	ResourceID uint64 `json:"resource_id"`
	Generation uint64 `json:"generation"`
}
type StreamRef struct {
	Parent ResourceRef `json:"parent"`
	ID     uint64      `json:"id"`
}

// Failure retains protocol evidence independently from its impact scope. Cause
// is never reconstructed from error text. Failure does not authorize replay.
type Failure struct {
	Resource ResourceRef
	Stream   *StreamRef
	Scope    FailureScope
	Layer    FailureLayer
	Phase    Operation
	Origin   FailureOrigin
	Reason   FailureReason
	Code     string
	Cause    error
}

func (f *Failure) Error() string {
	if f == nil {
		return "<nil>"
	}
	layer, scope, reason := f.Layer, f.Scope, f.Reason
	if layer == "" {
		layer = LayerUnknown
	}
	if scope == "" {
		scope = ScopeUnknown
	}
	if reason == "" {
		reason = ReasonUnknown
	}
	prefix := string(layer)
	if f.Phase != "" {
		prefix += " " + string(f.Phase)
	}
	return fmt.Sprintf("%s(%s/%s): %v", prefix, scope, reason, f.Cause)
}
func (f *Failure) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.Cause
}
func WrapFailure(err error, metadata Failure) error {
	if err == nil {
		return nil
	}
	metadata.Cause = err
	if metadata.Stream != nil {
		stream := *metadata.Stream
		metadata.Stream = &stream
	}
	return &metadata
}

// ClassifyFailure classifies one error, retaining existing owner evidence.
// Call Failures for joined errors: classification policy must inspect every leaf.
func ClassifyFailure(err error) Failure {
	failures := Failures(err)
	if len(failures) == 0 {
		return Failure{}
	}
	return failures[0]
}

func mergeFailure(inner, outer Failure) Failure {
	if outer.Resource != (ResourceRef{}) {
		inner.Resource = outer.Resource
	}
	if outer.Stream != nil {
		stream := *outer.Stream
		inner.Stream = &stream
	}
	if outer.Scope != "" && outer.Scope != ScopeUnknown {
		inner.Scope = outer.Scope
	}
	if outer.Layer != "" && outer.Layer != LayerUnknown {
		inner.Layer = outer.Layer
	}
	if outer.Phase != "" {
		inner.Phase = outer.Phase
	}
	if outer.Origin != "" && outer.Origin != OriginUnknown {
		inner.Origin = outer.Origin
	}
	if outer.Reason != "" && outer.Reason != ReasonUnknown {
		inner.Reason = outer.Reason
	}
	if outer.Code != "" {
		inner.Code = outer.Code
	}
	return inner
}

// Failures walks every branch of errors.Join while carrying metadata on its
// enclosing wrappers. Plain wrappers remain as Cause so errors.Is/As still work.
func Failures(err error) []Failure {
	if err == nil {
		return nil
	}
	var out []Failure
	var walk func(error, Failure, error)
	walk = func(e error, inherited Failure, cause error) {
		if e == nil {
			return
		}
		if f, ok := e.(*Failure); ok {
			metadata := mergeFailure(*f, inherited)
			metadata.Cause = nil
			if f.Cause == nil {
				metadata.Cause = cause
				out = append(out, metadata)
				return
			}
			walk(f.Cause, metadata, f.Cause)
			return
		}
		if semantic, ok := classifyProtocol(e); ok {
			semantic = mergeFailure(semantic, inherited)
			semantic.Cause = cause
			out = append(out, semantic)
			return
		}
		if joined, ok := e.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				walk(child, inherited, child)
			}
			return
		}
		// Inspect wrappers to find typed metadata and joins; classification itself
		// occurs at the original branch root, preserving net.OpError information.
		if unwrapped, ok := e.(interface{ Unwrap() error }); ok && unwrapped.Unwrap() != nil {
			walk(unwrapped.Unwrap(), inherited, cause)
			return
		}
		base := classifyRaw(cause)
		base = mergeFailure(base, inherited)
		base.Cause = cause
		out = append(out, base)
	}
	walk(err, Failure{}, err)
	return out
}

func classifyRaw(err error) Failure {
	f := Failure{Scope: ScopeUnknown, Layer: LayerUnknown, Origin: OriginUnknown, Reason: ReasonUnknown, Cause: err}
	var op *net.OpError
	if errors.As(err, &op) {
		switch op.Net {
		case "tcp", "tcp4", "tcp6":
			f.Layer = LayerTCP
		case "udp", "udp4", "udp6":
			f.Layer = LayerUDP
		}
		switch op.Op {
		case "read":
			f.Phase = OpRead
		case "write":
			f.Phase = OpWrite
		case "dial":
			f.Phase = OpDial
		}
	}
	var certErr *tls.CertificateVerificationError
	var unknownCA x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	switch {
	case errors.As(err, &certErr), errors.As(err, &unknownCA), errors.As(err, &hostname), errors.As(err, &invalid):
		f.Layer, f.Reason, f.Scope = LayerTLS, ReasonAuth, ScopeOperation
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		f.Reason, f.Scope = ReasonDeadline, ScopeOperation
	case errors.Is(err, context.Canceled):
		f.Reason, f.Scope = ReasonCanceled, ScopeOperation
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		f.Reason = ReasonReset
	case errors.Is(err, syscall.ECONNREFUSED):
		f.Reason = ReasonRejected
	default:
		var timeout interface{ Timeout() bool }
		if errors.As(err, &timeout) && timeout.Timeout() {
			f.Reason, f.Scope = ReasonDeadline, ScopeOperation
		}
	}
	// net.ErrClosed is deliberately not proof of local cancellation or scope.
	return f
}

// Typed protocol errors are atomic evidence even when their Unwrap contains
// several compatibility sentinels (notably QUIC transport errors).
func classifyProtocol(err error) (Failure, bool) {
	f := Failure{Scope: ScopeUnknown, Layer: LayerUnknown, Origin: OriginPeer, Reason: ReasonProtocol, Cause: err}
	switch e := err.(type) {
	case *quic.StreamError:
		if !e.Remote {
			f.Origin = OriginLocalProtocol
		}
		f.Layer, f.Scope, f.Reason, f.Code = LayerQUIC, ScopeStream, ReasonReset, strconv.FormatUint(uint64(e.ErrorCode), 10)
	case *quic.TransportError:
		if !e.Remote {
			f.Origin = OriginLocalProtocol
		}
		f.Layer, f.Scope, f.Code = LayerQUIC, ScopeSharedResource, strconv.FormatUint(uint64(e.ErrorCode), 10)
	case *quic.ApplicationError:
		if !e.Remote {
			f.Origin = OriginLocalProtocol
		}
		f.Layer, f.Scope, f.Code = LayerQUIC, ScopeSharedResource, strconv.FormatUint(uint64(e.ErrorCode), 10)
	case *quic.StatelessResetError:
		f.Layer, f.Scope, f.Reason = LayerQUIC, ScopeSharedResource, ReasonReset
	case *quic.IdleTimeoutError, *quic.HandshakeTimeoutError:
		f.Layer, f.Scope, f.Reason = LayerQUIC, ScopeSharedResource, ReasonDeadline
	case quic.StreamLimitReachedError, *quic.StreamLimitReachedError:
		f.Layer, f.Scope, f.Reason = LayerQUIC, ScopeOperation, ReasonCapacity
	case *quic.VersionNegotiationError:
		f.Layer, f.Scope = LayerQUIC, ScopeSharedResource
	case *http3.Error:
		if cause := e.Unwrap(); cause != nil {
			f = ClassifyFailure(cause)
		}
		f.Layer, f.Code = LayerH3, strconv.FormatUint(uint64(e.ErrorCode), 10)
	case http2.StreamError:
		f.Layer, f.Scope, f.Reason, f.Code = LayerH2, ScopeStream, ReasonReset, strconv.FormatUint(uint64(e.Code), 10)
	case http2.ConnectionError:
		f.Layer, f.Scope, f.Code = LayerH2, ScopeSharedResource, strconv.FormatUint(uint64(e), 10)
	case http2.GoAwayError:
		f.Layer, f.Scope, f.Reason, f.Code = LayerH2, ScopeOperation, ReasonRejected, strconv.FormatUint(uint64(e.ErrCode), 10)
	case interface{ GRPCStatus() *status.Status }:
		rpcStatus := e.GRPCStatus()
		if rpcStatus == nil {
			return f, false
		}
		f.Layer, f.Scope, f.Code = LayerGRPC, ScopeStream, rpcStatus.Code().String()
		switch rpcStatus.Code() {
		case codes.DeadlineExceeded:
			f.Scope, f.Reason = ScopeOperation, ReasonDeadline
		case codes.Canceled:
			f.Scope, f.Reason = ScopeOperation, ReasonCanceled
		case codes.ResourceExhausted:
			f.Scope, f.Reason = ScopeOperation, ReasonCapacity
		case codes.Unauthenticated, codes.PermissionDenied:
			f.Reason = ReasonAuth
		case codes.Unavailable:
			f.Reason = ReasonRejected
		}
	default:
		// Go's bundled HTTP/2 implementation can expose public x/net error
		// evidence via As while retaining its internal concrete type.
		if _, ok := err.(interface{ As(any) bool }); ok {
			var stream http2.StreamError
			if errors.As(err, &stream) {
				return classifyProtocol(stream)
			}
		}
		return f, false
	}
	return f, true
}
