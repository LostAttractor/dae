/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/pkg/outbound/common/url"
	"github.com/daeuniverse/dae/pkg/proxylink"
)

type FromLinkCreator func(link string) (builder Builder, property *Property, err error)

var fromLinkCreators = make(map[string]FromLinkCreator)

func FromLinkRegister(name string, creator FromLinkCreator) {
	fromLinkCreators[strings.ToLower(name)] = creator
}

func NewFromLink(link string) (Builder, *Property, error) {
	/// Get overwritten name.
	overwrittenName, linklike := proxylink.SplitTag(link)
	linklike = strings.TrimSpace(linklike)
	u, err := url.Parse(linklike)
	if err != nil {
		// Both the outer URL error and its cause can contain credentials:
		// malformed delimiters can make a password look like an invalid port.
		return nil, nil, fmt.Errorf("parse proxy URL: %w", InvalidParameterErr)
	}
	creator, ok := fromLinkCreators[strings.ToLower(u.Scheme)]
	if !ok {
		return nil, nil, fmt.Errorf("unexpected link type: %v", u.Scheme)
	}
	s, property, err := creator(linklike)
	if err != nil {
		return nil, nil, fmt.Errorf("create %s proxy: %w", u.Scheme, err)
	}
	if overwrittenName != "" {
		property.Name = overwrittenName
	}
	return s, property, nil
}
