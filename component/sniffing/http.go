/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"strings"

	"github.com/daeuniverse/dae/common"
)

func (s *Sniffer) SniffHttp() (d string, err error) {
	if s.buf.Len() == 0 {
		return "", ErrNotApplicable
	}

	// Search method.
	search := s.buf.Bytes()
	if len(search) > 12 {
		search = search[:12]
	}
	method, _, found := bytes.Cut(search, []byte(" "))
	if !found {
		// A read may end in the method itself. Only uppercase prefixes can
		// still become one of the supported methods on the next read.
		for _, c := range search {
			if c < 'A' || c > 'Z' {
				return "", ErrNotApplicable
			}
		}
		if len(search) == 12 {
			return "", ErrNotApplicable
		}
		return "", ErrNeedMore
	}
	if !common.IsValidHttpMethod(string(method)) {
		return "", ErrNotApplicable
	}

	// Inspect complete lines only. A partial Host value must never become
	// a routing decision, and an incomplete header is not a missing Host.
	remaining := s.buf.Bytes()
	for {
		line, rest, complete := bytes.Cut(remaining, []byte("\r\n"))
		if !complete {
			return "", ErrNeedMore
		}
		if len(line) == 0 {
			return "", ErrNotFound
		}
		remaining = rest
		key, value, found := bytes.Cut(line, []byte{':'})
		if !found {
			// Bad key value.
			continue
		}
		if strings.EqualFold(string(key), "host") {
			return string(value), nil
		}
	}
}
