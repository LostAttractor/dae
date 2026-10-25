package netproxy

import (
	"errors"
	"io"
	"time"
)

var ErrMissingDialer = errors.New("layer has no dialer")

// CloseLinger bounds each graceful close: how long one closing connection or
// resource waits to hand the peer what it already accepted. The bound is per
// layer: a resource whose carrier lingers as well waits for both in turn.
//
// Closing a connection keeps the bytes its Write accepted and the FIN its
// CloseWrite sent. Where they still wait in a process-local queue, Close
// either waits up to CloseLinger for them to leave or leaves them to the
// resource that owns the queue. A Runtime closes its Layer as soon as the
// last connection of a retired chain is closed.
const CloseLinger = 5 * time.Second

// Layer is the explicit result of building one or more outbound layers.
// Sessions and Resources are ordered from the inner layer to the outer layer.
type Layer struct {
	Data     Dialer
	Sessions []Session
	// Resources are closed only once every lease on them is released. A
	// resource that carries streams over a carrier first hands its queued
	// frames to the carrier, within CloseLinger, and closes at once when the
	// carrier has already failed or its owner aborted it. Closing the carrier
	// right after can still drop frames the peer has not read where the
	// carrier resets on Close, such as a stream of an earlier hop or a TCP
	// connection with unread data. sing-mux sessions therefore half-close
	// the carrier and wait for the peer's EOF within the same CloseLinger;
	// anytls sessions and HTTP/2 CONNECT pools still close it at once.
	Resources []io.Closer
}

// Append adds an outer layer and transfers its declared lifecycle into l.
func (l *Layer) Append(next Layer) error {
	if next.Data == nil {
		return ErrMissingDialer
	}
	l.Data = next.Data
	l.Sessions = append(l.Sessions, next.Sessions...)
	l.Resources = append(l.Resources, next.Resources...)
	return nil
}

// AppendResult appends a successful nested build result.
func (l *Layer) AppendResult(next Layer, err error) error {
	if err != nil {
		return err
	}
	return l.Append(next)
}

// Close releases Resources from the outside in. Sessions are never closed separately.
func (l Layer) Close() error {
	var err error
	for i := len(l.Resources) - 1; i >= 0; i-- {
		if l.Resources[i] != nil {
			err = errors.Join(err, l.Resources[i].Close())
		}
	}
	return err
}
