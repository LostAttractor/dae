// SPDX-License-Identifier: AGPL-3.0-only

package testutil

import (
	"context"
	"errors"
	"net"
)

// InstallOfflineResolver makes net.DefaultResolver fail every DNS exchange.
// TestMain calls it before tests start. A system resolver dials its server
// through a zero net.Dialer, which reads net.DefaultResolver from a lookup
// goroutine that can outlive its test and race with a later test replacing
// the resolver. Hosts-file answers still work.
func InstallOfflineResolver() {
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("test resolver is offline")
	}}
}
