// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"context"
	"sync"

	"github.com/daeuniverse/dae/api"
	dns "github.com/miekg/dns"
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
	// Declarative transformations carry private copies, including all DNS flags
	// and EDNS options. A terminal DNS message may instead contain a local reply.
	HTTP *api.DiagnosticHTTP
	DNS  *dns.Msg
	// Dials are possible first transport attempts owned by this middleware.
	// Multiple entries remain candidates, never an invented race winner.
	Dials []DiagnosticDial
	// DNSQuery is the query reaching the raw upstream boundary after middleware.
	DNSQuery *DNSRequest
	// CacheHit describes a raw upstream answer, not a final policy response.
	CacheHit bool
}

type DiagnosticDial struct {
	Protocol string
	Endpoint string // Full DNS resolver identity when known, including HTTP path/query.
	Target   api.DiagnosticTarget
}

type diagnosticDNSKey struct{}

// WithDiagnosticDNSRequest carries the canonical query and any known routing identity.
// Leave Upstream empty until the actual endpoint and routing policy are known.
func WithDiagnosticDNSRequest(ctx context.Context, request DNSRequest) context.Context {
	return context.WithValue(ctx, diagnosticDNSKey{}, request)
}

// DiagnosticDNSRequest returns query data even when routing identity is incomplete.
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
