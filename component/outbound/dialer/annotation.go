/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

const (
	AnnotationKey_AddLatency = "add_latency"
	AnnotationKey_Priority   = "priority"
)

type Priority struct {
	Pri  int
	Low  time.Duration
	High time.Duration
}

type PriorityTerm struct {
	Default     int
	Conditional []*Priority
}

type Annotation struct {
	AddLatency time.Duration
	Priority   int
	// Optional conditional priorities based on latency range.
	ConditionalPriority []*Priority
	// PriorityTerms preserves independently evaluated priority annotations from
	// every stage of an expanded proxy path.
	PriorityTerms []*PriorityTerm
}

func NewAnnotation(annotation []*config_parser.Param) (*Annotation, error) {
	var anno Annotation
	seen := make(map[string]struct{}, len(annotation))
	for _, param := range annotation {
		if _, ok := seen[param.Key]; ok {
			return nil, fmt.Errorf("duplicate path-stage annotation: %v", param.Key)
		}
		seen[param.Key] = struct{}{}
		switch param.Key {
		case AnnotationKey_AddLatency:
			latency, err := time.ParseDuration(param.Val)
			if err != nil {
				return nil, fmt.Errorf("incorrect latency format: %w", err)
			}
			anno.AddLatency = latency
		case AnnotationKey_Priority:
			// <default priority>; <priority>(<latency_low>,<latency_high>); <more...>
			reDefault := regexp.MustCompile(`^\s*(\d+)\s*`)
			defaultMatch := reDefault.FindStringSubmatch(param.Val)
			if defaultMatch == nil {
				return nil, fmt.Errorf("incorrect priority format: %v", param.Val)
			}
			priority, err := strconv.Atoi(defaultMatch[1])
			if err != nil {
				return nil, fmt.Errorf("incorrect priority number: %w", err)
			}
			anno.Priority = priority
			reConditional := regexp.MustCompile(`(\d+)\(([^,]*),([^,]*)\)`)
			conditionalMatches := reConditional.FindAllStringSubmatch(param.Val, -1)
			for _, conditionalMatch := range conditionalMatches {
				pri, err := strconv.Atoi(conditionalMatch[1])
				if err != nil {
					return nil, fmt.Errorf("incorrect priority number: %w", err)
				}
				lowStr := strings.TrimSpace(conditionalMatch[2])
				highStr := strings.TrimSpace(conditionalMatch[3])
				low := time.Duration(0)
				if lowStr != "" {
					low, err = time.ParseDuration(lowStr)
					if err != nil {
						return nil, fmt.Errorf("incorrect priority low: %w", err)
					}
				}

				high := time.Duration(math.MaxInt64)
				if highStr != "" {
					high, err = time.ParseDuration(highStr)
					if err != nil {
						return nil, fmt.Errorf("incorrect priority high: %w", err)
					}
				}
				anno.ConditionalPriority = append(anno.ConditionalPriority, &Priority{
					Pri:  pri,
					Low:  low,
					High: high,
				})
			}
			anno.PriorityTerms = []*PriorityTerm{{
				Default:     anno.Priority,
				Conditional: anno.ConditionalPriority,
			}}
		default:
			return nil, fmt.Errorf("unknown path-stage annotation: %v", param.Key)
		}
	}
	return &anno, nil
}

func (a *Annotation) PriorityAt(latency time.Duration) int {
	if len(a.PriorityTerms) == 0 {
		for _, p := range a.ConditionalPriority {
			if latency >= p.Low && latency <= p.High {
				return p.Pri
			}
		}
		return a.Priority
	}

	priority := 0
	for _, term := range a.PriorityTerms {
		termPriority := term.Default
		for _, p := range term.Conditional {
			if latency >= p.Low && latency <= p.High {
				termPriority = p.Pri
				break
			}
		}
		priority += termPriority
	}
	return priority
}

// MergeAnnotations combines scoring annotations from all path stages.
func MergeAnnotations(annotations ...*Annotation) (*Annotation, error) {
	merged := new(Annotation)
	maxInt := int(^uint(0) >> 1)
	minInt := -maxInt - 1
	for _, annotation := range annotations {
		if annotation == nil {
			continue
		}
		if annotation.AddLatency > 0 && merged.AddLatency > time.Duration(math.MaxInt64)-annotation.AddLatency ||
			annotation.AddLatency < 0 && merged.AddLatency < time.Duration(math.MinInt64)-annotation.AddLatency {
			return nil, fmt.Errorf("add_latency overflow")
		}
		merged.AddLatency += annotation.AddLatency
		if annotation.Priority > 0 && merged.Priority > maxInt-annotation.Priority ||
			annotation.Priority < 0 && merged.Priority < minInt-annotation.Priority {
			return nil, fmt.Errorf("priority overflow")
		}
		merged.Priority += annotation.Priority
		if len(annotation.PriorityTerms) > 0 {
			merged.PriorityTerms = append(merged.PriorityTerms, annotation.PriorityTerms...)
		} else if annotation.Priority != 0 || len(annotation.ConditionalPriority) > 0 {
			merged.PriorityTerms = append(merged.PriorityTerms, &PriorityTerm{
				Default:     annotation.Priority,
				Conditional: annotation.ConditionalPriority,
			})
		}
	}
	minPriority, maxPriority := 0, 0
	for _, term := range merged.PriorityTerms {
		termMin, termMax := term.Default, term.Default
		for _, conditional := range term.Conditional {
			termMin = min(termMin, conditional.Pri)
			termMax = max(termMax, conditional.Pri)
		}
		if termMin < 0 && minPriority < minInt-termMin || termMin > 0 && minPriority > maxInt-termMin ||
			termMax < 0 && maxPriority < minInt-termMax || termMax > 0 && maxPriority > maxInt-termMax {
			return nil, fmt.Errorf("conditional priority overflow")
		}
		minPriority += termMin
		maxPriority += termMax
	}
	return merged, nil
}
