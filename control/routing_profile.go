/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "github.com/daeuniverse/dae/internal/routingabi"

const maxRoutingInterfaces = routingabi.MAX_INTERFACE_NUM

type routingSpan struct {
	Start uint32
	End   uint32
	Phase routingPhase
	// Global marks system/plugin rules, whose scope is independent of policy.
	Global bool
}

type routingPhase uint8

const (
	routingPhaseRoute routingPhase = iota
	// Ingress includes API bypass and original-target capture. Userspace skips
	// it after selecting a target, regardless of the physical instruction order.
	routingPhaseIngress
	routingPhaseFlow
)

func (s routingSpan) len() int {
	return int(s.End - s.Start)
}

type routingProfile struct {
	ID             uint32
	Name           string
	InterfaceNames []string
	Spans          []routingSpan
	Destination    DestinationProgram
}

func appendSpan(spans []routingSpan, span routingSpan) []routingSpan {
	if span.Start == span.End {
		return spans
	}
	if len(spans) > 0 && spans[len(spans)-1].End == span.Start && spans[len(spans)-1].Phase == span.Phase && spans[len(spans)-1].Global == span.Global {
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
