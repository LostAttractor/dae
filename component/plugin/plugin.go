// SPDX-License-Identifier: AGPL-3.0-only

// Package plugin defines protocol-independent plugin lifecycle and optional capabilities.
package plugin

import (
	"context"
	"net/http"
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/prometheus/client_golang/prometheus"
	logrus "github.com/sirupsen/logrus"
)

// Flow retains the original captured Source/Destination tuple. Host/Port identify
// the incoming authority admitted before middleware; H2/H3 fronting can select a
// different business host on the same connection. It is not proof of TLS identity.
type Flow struct {
	Host                string
	Port                uint16
	Source, Destination netip.AddrPort
	// SourceMAC is the original kernel ingress identity, or zero for callers
	// without LAN metadata. It is independent of per-destination IP selection.
	SourceMAC [6]byte
}

// Exchange belongs to one synchronous invocation. Background work must copy
// the required data instead of retaining the request, body or response writer.
type Exchange struct {
	Request *http.Request
	Client  *http.Client
	// SetReadDeadline bounds reads from the intercepted request body. The host
	// resets the deadline when calling next. Nil means unsupported (e.g. tests).
	SetReadDeadline func(time.Time) error
}

// Handler calls next synchronously. On success it returns a valid response
// with non-nil Header and Body, transferring body ownership to its caller.
// On error it closes any owned response body and returns nil, err.
// The host associates next's response with Exchange.Request before returning it.
type Handler func(*Exchange) (*http.Response, error)

// Plan is immutable after preparation; the host takes ownership without copying it.
type Plan struct {
	// RequiredOutbounds keeps auxiliary-request policies loaded without adding routing or capture rules.
	RequiredOutbounds   []string
	DNS                 []DNSScope
	Scopes              []HTTPScope
	Destinations        routing.DestinationRewrites
	EarlyRoutes, Routes []*config_parser.RoutingRule
}

// HTTPScope couples an interception scope with its routing effect. Requests
// are processed before routing unless the plugin declares that it preserves
// the target and cannot answer locally. Effects cannot expand the scope.
type HTTPScope struct {
	Scope
	PreserveRoute bool
}

type Plugin interface {
	Plan() Plan
}

// HTTPPlugin is optional. DNS-only and routing-only plugins need no HTTP handler.
type HTTPPlugin interface {
	Plugin
	Wrap(Flow, Handler) Handler
}

// Worker runs once after activation; errors are logged. It must honor ctx
// cancellation and join its goroutines before returning.
type Worker interface {
	Run(context.Context, *http.Client) error
}

type Spec struct {
	ID, Type string
	Config   *config_parser.Section
}

// Services is provided by the host to factories. Logger is non-nil and includes
// the instance ID; PrepareClient is for preparation only, never background work.
type Services struct {
	// Prepared contains the immutable value returned by Definition.Resources.
	Prepared any
	// ResourceCacheDir is empty when global resource caching is disabled.
	ResourceCacheDir string
	BaseDir          string
	Logger           *logrus.Entry
	PrepareClient    *http.Client
	// BodyMemory is the host-owned process budget, shared across reloads.
	BodyMemory *membuffer.Budget
	// Storage persists opaque values in this type/instance's namespace. The host
	// supplies it when BaseDir is nonempty; direct factory callers may leave it nil.
	// Preparation must only read: failed/replaced preparations can be closed
	// without activation. Reload-sensitive state should be read after activation.
	Storage Storage
	// Metrics registers instance-owned collectors during preparation. The host adds
	// dae_plugin_ and the plugin_type/plugin_instance labels. Collect must be
	// concurrency-safe, perform no I/O and finish promptly. Nil is allowed for
	// direct factory callers. Counters reset when the instance is reconstructed.
	Metrics prometheus.Registerer
}

// Factory prepares resources without starting workers. On error it must release
// its own partial state; on success the host takes ownership of the plugin.
type Factory func(context.Context, Services) (Plugin, error)

// Resources identifies a complete, validated set of external inputs. Key must
// include every input affecting the instance; Value is passed to its factory.
// It owns no workers, connections or other resources requiring cleanup.
type Resources struct {
	// Config optionally supplies the parsed, defaulted configuration used for
	// equality. When nil, the host compares Spec.Config conservatively.
	Config any
	Key    string
	Value  any
}

// Reporter returns a JSON-serializable status snapshot, excluding configuration
// credentials. Explicit script output may be included as documented by the plugin.
type Reporter interface{ Report() any }
