// SPDX-License-Identifier: AGPL-3.0-only

// Package plugin defines protocol-independent plugin lifecycle and optional capabilities.
package plugin

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/prometheus/client_golang/prometheus"
	logrus "github.com/sirupsen/logrus"
)

// SourceOrigin comes only from verified ingress, never inferred from a MAC, IP or PID.
type SourceOrigin uint8

const (
	SourceUnknown SourceOrigin = iota
	SourceLocal
	SourceLAN
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
	SourceMAC    [6]byte
	SourceOrigin SourceOrigin
}

// Exchange belongs to one synchronous invocation. Background work must copy
// the required data instead of retaining the request, body or response writer.
type Exchange struct {
	Request *Request
	Client  *http.Client
	// SetReadDeadline bounds reads from the intercepted request body. The host
	// resets the deadline when calling next. Nil means unsupported (e.g. tests).
	SetReadDeadline func(time.Time) error
}

type Handler func(*Exchange) (*Response, error)

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

// SharedStates leases reload-independent state within one base directory, plugin
// type and instance. Keys must identify compatible state, including its storage
// path when configurable. The builder only allocates memory: it must not perform
// I/O or start workers. Restore persisted state lazily after activation instead.
//
// Each successful Acquire returns an idempotent release. Plugins must release
// every lease, including on factory failure, and must not call the state's Close
// directly. The last release closes the state; a failed Close must leave it usable
// for another lease and a later Close retry. Acquiring the same key waits for a
// pending build or Close, honoring ctx cancellation; unrelated keys do not wait.
// The host rejects new leases at shutdown and closes remaining states after all
// plugins have stopped. Standalone factories may use private state instead.
type SharedStates interface {
	Acquire(context.Context, string, func() (io.Closer, error)) (io.Closer, func() error, error)
}

// DeviceService provides host-verified identities and MITM-enabled devices across reloads.
// Identify returns a zero MAC for unverified direct clients; MITMEnabled returns a detached, deduplicated snapshot.
type DeviceService interface {
	Identify(context.Context, netip.Addr, [6]byte) [6]byte
	MITMEnabled(context.Context) ([][6]byte, error)
}

// Services is provided by the host to factories. Logger is non-nil and includes
// the instance ID; PrepareClient is for preparation only, never background work.
type Services struct {
	// Interfaces is a borrowed host event source. Plugins own NewScope results
	// and close those scopes, never the source. Nil supports standalone factories.
	Interfaces *network.InterfaceManager
	// Devices is host-owned; without it, LAN identities and background device targets cannot be verified.
	Devices DeviceService
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
	// SharedStates is host-owned and scoped to this base directory/type/instance.
	// Nil supports standalone factories; leases belong to the plugin, not the host.
	SharedStates SharedStates
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

// ResourceObserver accepts refreshed metadata after its candidate is published,
// including when Key is unchanged and the instance is reused. It must be safe
// alongside requests and reports, and must not fail, perform I/O or replace the
// instance's runtime inputs. Abandoned preparations never invoke it.
type ResourceObserver interface{ AcceptResources(any) }

// Reporter returns a JSON-serializable status snapshot, excluding configuration
// credentials. Explicit script output may be included as documented by the plugin.
type Reporter interface{ Report() any }
