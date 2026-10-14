// SPDX-License-Identifier: AGPL-3.0-only

package http2

import "io"

// TryReadEOF reports a clean end of the request without waiting for network
// input or consuming body bytes. On success, the request's final trailers are
// available, just as after Read returns io.EOF. False with a nil error means
// the request is not yet known to be exhausted; an error is an abnormal end.
// Like Read, it must not be called concurrently with another body reader.
func (b *requestBody) TryReadEOF() (bool, error) {
	if b.pipe == nil || b.sawEOF {
		return true, nil
	}
	p := b.pipe
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.breakErr != nil {
		return false, p.breakErr
	}
	if p.b != nil && p.b.Len() != 0 || p.err == nil {
		return false, nil
	}
	if p.err != io.EOF {
		return false, p.err
	}
	if p.readFn != nil {
		p.readFn()
		p.readFn = nil
	}
	p.b = nil
	b.sawEOF = true
	return true, nil
}
