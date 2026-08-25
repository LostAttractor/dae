/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"strconv"
	"strings"
)

type Item struct {
	Value any
}

func newItem(value any) *Item {
	return &Item{Value: value}
}

func indent(value string) string { return "\t" + strings.ReplaceAll(value, "\n", "\n\t") }

func (i *Item) TypeName() string {
	switch i.Value.(type) {
	case *RoutingRule:
		return "RoutingRule"
	case *ProxyPath:
		return "ProxyPath"
	case *Param:
		return "Param"
	case *Section:
		return "Section"
	default:
		return "<Unknown>"
	}
}

func (i *Item) String(compact bool, quoteVal bool) string {
	var content string
	switch val := i.Value.(type) {
	case *RoutingRule:
		content = val.String(false, compact, quoteVal)
	case *ProxyPath:
		content = val.String(compact, quoteVal)
	case *Param:
		content = val.String(false, quoteVal)
	case *Section:
		content = val.String(compact, quoteVal)
	default:
		return "<Unknown>\n"
	}
	return "type: " + i.TypeName() + "\n" + indent(content)
}

type Section struct {
	Name  string
	Items []*Item
}

func (s *Section) String(compact bool, quoteVal bool) string {
	items := make([]string, 0, len(s.Items))
	for _, item := range s.Items {
		items = append(items, indent(item.String(compact, quoteVal)))
	}
	return "section: " + s.Name + "\n" + strings.Join(items, "\n")
}

type Param struct {
	// Key may be empty.
	Key string

	// Either Val or AndFunctions is empty.
	Val          string
	AndFunctions []*Function
	// Quoted is retained for declaration literals whose lexical form affects
	// routing target resolution.
	Quoted bool

	// Annotation is optional
	Annotation []*Param
}

func (p *Param) String(compact bool, quoteVal bool) string {
	var quote func(string) string
	if quoteVal {
		quote = quoteLiteral
	} else {
		quote = func(s string) string { return s }
	}
	var value string
	if p.AndFunctions != nil {
		functions := make([]string, 0, len(p.AndFunctions))
		for _, function := range p.AndFunctions {
			functions = append(functions, function.String(compact, quoteVal, false))
		}
		separator := " && "
		if compact {
			separator = "&&"
		}
		value = strings.Join(functions, separator)
	} else {
		value = quote(p.Val)
	}
	if p.Key != "" {
		separator := ": "
		if compact {
			separator = ":"
		}
		value = p.Key + separator + value
	}
	if len(p.Annotation) != 0 {
		annotations := make([]string, 0, len(p.Annotation))
		for _, annotation := range p.Annotation {
			annotations = append(annotations, annotation.String(compact, quoteVal))
		}
		separator := ", "
		if compact {
			separator = ","
		}
		value += " [" + strings.Join(annotations, separator) + "]"
	}
	return value
}

func quoteLiteral(value string) string {
	var builder strings.Builder
	builder.Grow(len(value) + 2)
	builder.WriteByte('"')
	for i := 0; i < len(value); i++ {
		if value[i] == '"' || value[i] == '\\' {
			builder.WriteByte('\\')
		}
		builder.WriteByte(value[i])
	}
	builder.WriteByte('"')
	return builder.String()
}

type Function struct {
	Name   string
	Not    bool
	Params []*Param
	// Quoted distinguishes literal target names from legacy name shorthands.
	Quoted bool
}

func isBareLiteral(s string) bool {
	const head = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_/\\^*.+0123456789-"
	const rest = head + "=@$!#%"
	return s != "" && strings.ContainsRune(head, rune(s[0])) &&
		strings.IndexFunc(s[1:], func(r rune) bool { return !strings.ContainsRune(rest, r) }) == -1
}

func formatFunctionName(name string, quoted bool) string {
	if quoted || !isBareLiteral(name) {
		return quoteLiteral(name)
	}
	return name
}

func (f *Function) String(compact bool, quoteVal bool, omitEmpty bool) string {
	var builder strings.Builder
	if f.Not {
		builder.WriteString("!")
	}
	builder.WriteString(formatFunctionName(f.Name, f.Quoted))
	if !(omitEmpty && len(f.Params) == 0) {
		builder.WriteString("(")
		var strParamList []string
		for _, p := range f.Params {
			strParamList = append(strParamList, p.String(compact, quoteVal))
		}
		separator := ", "
		if compact {
			separator = ","
		}
		builder.WriteString(strings.Join(strParamList, separator))
		builder.WriteString(")")
	}
	return builder.String()
}

type RoutingRule struct {
	AndFunctions []*Function
	Outbound     Function
}

type ProxyPath struct {
	Stages []*Param
}

func (p *ProxyPath) String(compact bool, quoteVal bool) string {
	stages := make([]string, 0, len(p.Stages))
	for _, stage := range p.Stages {
		stages = append(stages, stage.String(compact, quoteVal))
	}
	separator := " -> "
	if compact {
		separator = "->"
	}
	return strings.Join(stages, separator)
}

func (r *RoutingRule) String(replaceParamWithN bool, compact bool, quoteVal bool) string {
	functions := make([]string, 0, len(r.AndFunctions))
	for _, function := range r.AndFunctions {
		if replaceParamWithN {
			name := formatFunctionName(function.Name, function.Quoted)
			if function.Not {
				name = "!" + name
			}
			functions = append(functions, name+"([n = "+strconv.Itoa(len(function.Params))+"])")
		} else {
			functions = append(functions, function.String(compact, quoteVal, false))
		}
	}
	and, arrow := " && ", " -> "
	if compact {
		and, arrow = "&&", "->"
	}
	return strings.Join(functions, and) + arrow + r.Outbound.String(compact, quoteVal, true)
}
