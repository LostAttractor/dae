package obfs

import (
	mathrand "math/rand/v2"
)

// newHttpPost create a http_post object
func newHttpPost() IObfs {
	// newHttpSimple create a http_simple object

	t := &httpSimplePost{
		userAgentIndex: mathrand.IntN(len(requestUserAgent)),
		methodGet:      false,
	}
	return t
}
