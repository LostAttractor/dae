// SPDX-License-Identifier: AGPL-3.0-only
//go:build no_webui

package webui

import (
	"net/http"
	"net/netip"
)

func Handler(string, ...netip.AddrPort) http.Handler { return http.NotFoundHandler() }
