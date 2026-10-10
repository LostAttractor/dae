// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"context"
	"sync"

	"github.com/daeuniverse/dae/api"
)

// Explainer is an optional pure capability. Implementations must not perform
// network I/O, invoke scripts, update metrics, refresh LRU entries or acquire
// connection leases. Inputs carry data only, never execution services.
type Explainer interface {
	Explain(context.Context, api.ExplainRequest) Explanation
}

type Explanation struct {
	Steps    []api.ExplainStep
	Complete bool
	Terminal bool
	// A declarative request transformation can be passed to the next plugin.
	HTTP *api.DiagnosticHTTP
	DNS  *api.DiagnosticDNS
	// Dials are possible first transport attempts owned by this middleware.
	// Multiple entries remain candidates, never an invented race winner.
	Dials []DiagnosticDial
}

type DiagnosticDial struct {
	Protocol string
	Target   api.DiagnosticTarget
}

type diagnosticDNSKey struct{}

// WithDiagnosticDNSRequest carries a fully known cache identity as data only.
// A missing value means an explainer must not claim an exact cache hit/miss.
func WithDiagnosticDNSRequest(ctx context.Context, request DNSRequest) context.Context {
	return context.WithValue(ctx, diagnosticDNSKey{}, request)
}

func DiagnosticDNSRequest(ctx context.Context) (DNSRequest, bool) {
	request, ok := ctx.Value(diagnosticDNSKey{}).(DNSRequest)
	return request, ok
}

type diagnosticSamplesKey struct{}

// DiagnosticSamples pins non-mutating observations for one explanation and its
// comparisons. Keys must be comparable and include the plugin instance.
type DiagnosticSamples struct {
	mu     sync.Mutex
	values map[any]any
}

func WithDiagnosticSamples(ctx context.Context) context.Context {
	return context.WithValue(ctx, diagnosticSamplesKey{}, &DiagnosticSamples{values: make(map[any]any)})
}

func SamplesForDiagnostics(ctx context.Context) *DiagnosticSamples {
	samples, _ := ctx.Value(diagnosticSamplesKey{}).(*DiagnosticSamples)
	return samples
}

// Returned values must be treated as immutable. A standalone plugin call
// without a session still samples exactly once for that call.
func (s *DiagnosticSamples) Sample[T any](key any, read func() T) T {
	if s == nil {
		return read()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if value, ok := s.values[key]; ok {
		return value.(T)
	}
	value := read()
	s.values[key] = value
	return value
}
