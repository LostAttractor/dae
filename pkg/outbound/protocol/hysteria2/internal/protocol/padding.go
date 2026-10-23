package protocol

import (
	mathrand "math/rand/v2"
)

const (
	paddingChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// padding specifies a half-open range [Min, Max).
type padding struct {
	Min int
	Max int
}

func (p padding) String() string {
	n := p.Min + mathrand.IntN(p.Max-p.Min)
	bs := make([]byte, n)
	for i := range bs {
		bs[i] = paddingChars[mathrand.IntN(len(paddingChars))]
	}
	return string(bs)
}

var (
	authRequestPadding = padding{Min: 256, Max: 2048}
	tcpRequestPadding  = padding{Min: 64, Max: 512}
)
