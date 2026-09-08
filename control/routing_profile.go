/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"maps"
)

// Keep in sync with MAX_INTERFACE_NUM in control/kern/tproxy.c.
const maxRoutingInterfaces = 256

type routingSpan struct {
	Start uint32
	End   uint32
}

func (s routingSpan) len() int {
	return int(s.End - s.Start)
}

type routingProfile struct {
	ID             uint32
	InterfaceNames []string
	Spans          []routingSpan
}

// IDs belong to policy names, including the anonymous policy (empty name).
// Zero is reserved for callers without a kernel routing context.
type routingProfileIDAllocator struct {
	ids  map[string]uint32
	next uint64
}

func (a routingProfileIDAllocator) plan(names []string) (routingProfileIDAllocator, error) {
	plan := a
	plan.ids = maps.Clone(a.ids)
	if plan.ids == nil {
		plan.ids = make(map[string]uint32, len(names))
	}
	if plan.next == 0 {
		plan.next = 1
	}
	for _, name := range names {
		if _, ok := plan.ids[name]; ok {
			continue
		}
		if plan.next > uint64(^uint32(0)) {
			return routingProfileIDAllocator{}, fmt.Errorf("routing profile ID space exhausted")
		}
		plan.ids[name] = uint32(plan.next)
		plan.next++
	}
	return plan, nil
}

func appendSpan(spans []routingSpan, span routingSpan) []routingSpan {
	if span.Start == span.End {
		return spans
	}
	if len(spans) > 0 && spans[len(spans)-1].End == span.Start {
		spans[len(spans)-1].End = span.End
		return spans
	}
	return append(spans, span)
}

func spanExecutionLen(spans []routingSpan) int {
	length := 0
	for _, span := range spans {
		length += span.len()
	}
	return length
}
