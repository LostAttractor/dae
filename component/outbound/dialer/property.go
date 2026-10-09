/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"github.com/daeuniverse/dae/api"
	D "github.com/daeuniverse/outbound/dialer"
)

type Property struct {
	D.Property
	SubscriptionTag string
	Hops            []Hop
	Egress          *api.NodeEgress
}

type Hop struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Subtag   string `json:"subtag"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
}
