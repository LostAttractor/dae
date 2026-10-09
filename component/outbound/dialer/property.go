/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/selector"
	D "github.com/daeuniverse/outbound/dialer"
)

type Property struct {
	D.Property
	SubscriptionTag string
	Egress          *api.NodeEgress
	Selection       *selector.Path
}

// SelectionReference is independent of statistics, transport options and scope.
func (d *Dialer) SelectionReference() *selector.Path {
	if d.Property.Selection != nil {
		return d.Property.Selection.Clone()
	}
	// Single-node dialers constructed directly have no expanded path metadata.
	source := "local"
	if d.SubscriptionTag != "" {
		source = selector.SubscriptionSource(d.SubscriptionTag, "")
	}
	return &selector.Path{Nodes: []selector.Node{{Source: source, Name: d.Name, Fingerprint: selector.Fingerprint(d.Link), Exact: d.Name == ""}}}
}
