package netproxy

import (
	"errors"
	"io"
)

var ErrMissingDialer = errors.New("layer has no dialer")

// Layer is the explicit result of building one or more outbound layers.
// Sessions and Resources are ordered from the inner layer to the outer layer.
type Layer struct {
	Data      Dialer
	Sessions  []Session
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
