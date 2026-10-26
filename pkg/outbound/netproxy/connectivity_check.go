// SPDX-License-Identifier: AGPL-3.0-only

package netproxy

import "context"

type connectivityCheckKey struct{}

// WithConnectivityCheck marks dials made by connectivity checks. Pooled
// transports serve them from existing capacity and never grow for them.
func WithConnectivityCheck(ctx context.Context) context.Context {
	return context.WithValue(ctx, connectivityCheckKey{}, true)
}

func IsConnectivityCheck(ctx context.Context) bool {
	check, _ := ctx.Value(connectivityCheckKey{}).(bool)
	return check
}

type quicKey struct{}

// WithQUIC marks the dial of a UDP association that carries QUIC, as
// sniffed from its first datagram. Pooled transports keep such bulk
// datagram flows apart from interactive ones.
func WithQUIC(ctx context.Context) context.Context {
	return context.WithValue(ctx, quicKey{}, true)
}

func IsQUIC(ctx context.Context) bool {
	quic, _ := ctx.Value(quicKey{}).(bool)
	return quic
}
