/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

// Keep in sync with the internal MAX_INTERFACE_NUM in control/kern/tproxy.c.
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
