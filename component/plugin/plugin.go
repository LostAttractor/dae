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
	logrus "github.com/sirupsen/logrus"
)

// Flow retains the original captured Source/Destination tuple. Host/Port identify
// the incoming authority admitted before middleware; H2/H3 fronting can select a
// different business host on the same connection. It is not proof of TLS identity.
type Flow struct {
	Host                string
	Port                uint16
	Source, Destination netip.AddrPort
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
	BaseDir       string
	Logger        *logrus.Entry
	PrepareClient *http.Client
	// BodyMemory is the host-owned process budget, shared across reloads.
	BodyMemory *membuffer.Budget
}

// Factory prepares resources without starting workers. On error it must release
// its own partial state; on success the host takes ownership of the plugin.
type Factory func(context.Context, Services) (Plugin, error)

// Reporter returns a JSON-serializable, credential-free status snapshot.
type Reporter interface{ Report() any }
