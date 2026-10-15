package obfs

import (
	rand "github.com/daeuniverse/dae/pkg/outbound/pkg/fastrand"
)

// newHttpPost create a http_post object
func newHttpPost() IObfs {
	// newHttpSimple create a http_simple object

	t := &httpSimplePost{
		userAgentIndex: rand.Intn(len(requestUserAgent)),
		methodGet:      false,
	}
	return t
}
