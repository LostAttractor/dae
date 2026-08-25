/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"math"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func parseAnnotation(t *testing.T, params ...*config_parser.Param) *Annotation {
	t.Helper()
	anno, err := NewAnnotation(params)
	if err != nil {
		t.Fatal(err)
	}
	return anno
}

func TestNewAnnotation_AddLatency(t *testing.T) {
	anno := parseAnnotation(t, &config_parser.Param{Key: "add_latency", Val: "-500ms"})
	if anno.AddLatency != -500*time.Millisecond {
		t.Errorf("AddLatency: got %v", anno.AddLatency)
	}
}

func TestNewAnnotation_AddLatency_Invalid(t *testing.T) {
	if _, err := NewAnnotation([]*config_parser.Param{{Key: "add_latency", Val: "not-a-duration"}}); err == nil {
		t.Errorf("invalid add_latency should return an error")
	}
}

func TestNewAnnotationRejectsDuplicateKeys(t *testing.T) {
	if _, err := NewAnnotation([]*config_parser.Param{
		{Key: AnnotationKey_Priority, Val: "1"},
		{Key: AnnotationKey_Priority, Val: "2"},
	}); err == nil {
		t.Fatal("duplicate annotation key was accepted")
	}
}

func TestMergeAnnotationsRejectsOverflow(t *testing.T) {
	if _, err := MergeAnnotations(
		&Annotation{AddLatency: time.Duration(math.MaxInt64)},
		&Annotation{AddLatency: time.Nanosecond},
	); err == nil {
		t.Fatal("duration overflow was accepted")
	}
	maxInt := int(^uint(0) >> 1)
	if _, err := MergeAnnotations(
		&Annotation{PriorityTerms: []*PriorityTerm{{Default: maxInt}}},
		&Annotation{PriorityTerms: []*PriorityTerm{{Default: 1}}},
	); err == nil {
		t.Fatal("conditional priority overflow was accepted")
	}
}

func TestNewAnnotation_Priority(t *testing.T) {
	anno := parseAnnotation(t, &config_parser.Param{Key: "priority", Val: "3"})
	if anno.Priority != 3 {
		t.Errorf("Priority: got %v", anno.Priority)
	}
	if len(anno.ConditionalPriority) != 0 {
		t.Errorf("no conditional priority expected: %+v", anno.ConditionalPriority)
	}
}

func TestNewAnnotation_ConditionalPriority(t *testing.T) {
	anno := parseAnnotation(t, &config_parser.Param{Key: "priority", Val: "1; 2(100ms, 200ms); 3(, 500ms); 4(300ms,)"})
	if anno.Priority != 1 {
		t.Errorf("Priority: got %v", anno.Priority)
	}
	if len(anno.ConditionalPriority) != 3 {
		t.Fatalf("3 conditional priorities expected: %+v", anno.ConditionalPriority)
	}
	p := anno.ConditionalPriority[0]
	if p.Pri != 2 || p.Low != 100*time.Millisecond || p.High != 200*time.Millisecond {
		t.Errorf("conditional priority[0]: got %+v", p)
	}
	// Empty low defaults to 0.
	p = anno.ConditionalPriority[1]
	if p.Pri != 3 || p.Low != 0 || p.High != 500*time.Millisecond {
		t.Errorf("conditional priority[1]: got %+v", p)
	}
	// Empty high defaults to MaxInt64.
	p = anno.ConditionalPriority[2]
	if p.Pri != 4 || p.Low != 300*time.Millisecond || p.High != time.Duration(math.MaxInt64) {
		t.Errorf("conditional priority[2]: got %+v", p)
	}
}

func TestNewAnnotation_Priority_Invalid(t *testing.T) {
	if _, err := NewAnnotation([]*config_parser.Param{{Key: "priority", Val: "abc"}}); err == nil {
		t.Errorf("invalid priority should return an error")
	}
	if _, err := NewAnnotation([]*config_parser.Param{{Key: "priority", Val: "1; 2(abc, 200ms)"}}); err == nil {
		t.Errorf("invalid conditional priority low should return an error")
	}
}

func TestNewAnnotation_UnknownKey(t *testing.T) {
	if _, err := NewAnnotation([]*config_parser.Param{{Key: "unknown_annotation", Val: "1"}}); err == nil {
		t.Errorf("unknown annotation key should return an error")
	}
}
