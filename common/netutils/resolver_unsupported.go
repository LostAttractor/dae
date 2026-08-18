//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"errors"
	"net"
)

func newMarkedResolver(uint32) (*net.Resolver, error) {
	return nil, errors.New("marked resolver requires Linux SO_MARK support")
}
