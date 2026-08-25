/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// This file should trace https://github.com/daeuniverse/dae-config-dist/blob/main/dae_config.g4.

package config_parser

import (
	"strconv"
	"strings"

	"github.com/antlr/antlr4/runtime/Go/antlr/v4"

	"github.com/daeuniverse/dae-config-dist/go/dae_config"
)

type decoder struct {
	parser antlr.Parser
}

func getValueFromLiteral(literal *dae_config.LiteralContext) string {
	quote := literal.QUOTE_STRING()
	if quote == nil {
		return literal.GetText()
	}
	return getValueFromQuoteLiteral(quote.GetText())
}

func getValueFromQuoteLiteral(text string) string {
	if len(text) < 2 {
		return text
	}
	quote := text[0]
	content := text[1 : len(text)-1]
	var builder strings.Builder
	for i := 0; i < len(content); i++ {
		if content[i] == '\\' && i+1 < len(content) && (content[i+1] == quote || content[i+1] == '\\') {
			i++
		}
		builder.WriteByte(content[i])
	}
	return builder.String()
}

func parseParam(ctx *dae_config.ParameterContext) *Param {
	param := &Param{Val: getValueFromLiteral(ctx.Literal().(*dae_config.LiteralContext))}
	if key := ctx.ID(); key != nil {
		param.Key = key.GetText()
	}
	return param
}

func parseParams(input []dae_config.IParameterContext) []*Param {
	params := make([]*Param, 0, len(input))
	for _, param := range input {
		params = append(params, parseParam(param.(*dae_config.ParameterContext)))
	}
	return params
}

func (d *decoder) parseOptAnnotation(ctx dae_config.IOptAnnotationContext) []*Param {
	if ctx == nil {
		return nil
	}
	annotation := ctx.(*dae_config.OptAnnotationContext)
	var params []*Param
	for _, item := range annotation.AllAnnotationParameter() {
		item := item.(*dae_config.AnnotationParameterContext)
		if item.FunctionPrototype() != nil {
			message := "function-valued annotations are not supported"
			if item.ID().GetText() == "via" {
				message = "via annotations are no longer supported; compose proxy paths with ->"
			}
			d.reportError(item, message)
			continue
		}
		param := parseParam(item.Parameter().(*dae_config.ParameterContext))
		if param.Key == "via" {
			d.reportError(item, "via annotations are no longer supported; compose proxy paths with ->")
			continue
		}
		params = append(params, param)
	}
	return params
}

func (d *decoder) parseFunctionPrototype(ctx *dae_config.FunctionPrototypeContext) *Function {
	not := strings.HasPrefix(ctx.GetText(), "!")
	var funcName string
	quoted := false
	switch {
	case ctx.ID() != nil:
		funcName = ctx.ID().GetText()
	case ctx.NON_ID() != nil:
		funcName = ctx.NON_ID().GetText()
	case ctx.QUOTE_STRING() != nil:
		funcName = getValueFromQuoteLiteral(ctx.QUOTE_STRING().GetText())
		quoted = true
	default:
		d.reportError(ctx, "bad function name")
		return nil
	}
	parameters := ctx.AllParameter()
	if len(parameters) == 0 {
		d.reportError(ctx, "empty parameter list")
		return nil
	}
	return &Function{
		Name:   funcName,
		Not:    not,
		Params: parseParams(parameters),
		Quoted: quoted,
	}
}

func (d *decoder) reportError(ctx antlr.ParserRuleContext, target ...string) {
	tgt := strconv.Quote(ctx.GetStart().GetText())
	if len(target) != 0 {
		tgt = target[0]
	}
	d.parser.NotifyErrorListeners(tgt+" is not supported.", ctx.GetStart(), nil)
}

func (d *decoder) parseDeclaration(ctx dae_config.IDeclarationContext) *Param {
	declaration := ctx.(*dae_config.DeclarationContext)
	param := &Param{Key: declaration.ID().GetText()}
	if functions := declaration.AllFunctionPrototype(); len(functions) != 0 {
		andFunctions := d.parseFunctions(functions)
		if andFunctions == nil {
			return nil
		}
		param.AndFunctions = andFunctions
	} else {
		literals := declaration.AllLiteral()
		values := make([]string, 0, len(literals))
		for _, literal := range literals {
			values = append(values, getValueFromLiteral(literal.(*dae_config.LiteralContext)))
		}
		param.Val = strings.Join(values, ",")
		param.Quoted = len(literals) == 1 && literals[0].(*dae_config.LiteralContext).QUOTE_STRING() != nil
	}
	param.Annotation = d.parseOptAnnotation(declaration.OptAnnotation())
	return param
}

func (d *decoder) parseFunctions(functions []dae_config.IFunctionPrototypeContext) (andFunctions []*Function) {
	for _, function := range functions {
		parsed := d.parseFunctionPrototype(function.(*dae_config.FunctionPrototypeContext))
		if parsed == nil {
			return nil
		}
		andFunctions = append(andFunctions, parsed)
	}
	return andFunctions
}

func (d *decoder) parseRoutingRule(ctx dae_config.IArrowExpressionContext) *RoutingRule {
	operands := ctx.(*dae_config.ArrowExpressionContext).AllArrowOperand()
	if len(operands) != 2 {
		d.reportError(ctx, "routing rules require exactly two arrow operands")
		return nil
	}
	matcher := operands[0].(*dae_config.ArrowOperandContext)
	if matcher.ID() != nil || matcher.Literal() != nil || len(d.parseOptAnnotation(matcher.OptAnnotation())) != 0 {
		d.reportError(matcher, "bad routing matcher")
		return nil
	}
	functions := d.parseFunctions(matcher.AllFunctionPrototype())
	if functions == nil {
		return nil
	}

	target := operands[1].(*dae_config.ArrowOperandContext)
	if target.ID() != nil || len(d.parseOptAnnotation(target.OptAnnotation())) != 0 {
		d.reportError(target, "bad routing target")
		return nil
	}
	var outbound *Function
	if literal := target.Literal(); literal != nil {
		literal := literal.(*dae_config.LiteralContext)
		if quote := literal.QUOTE_STRING(); quote != nil {
			outbound = &Function{Name: getValueFromQuoteLiteral(quote.GetText()), Quoted: true}
		} else {
			outbound = &Function{Name: literal.GetText()}
		}
	} else {
		outbounds := d.parseFunctions(target.AllFunctionPrototype())
		if len(outbounds) != 1 {
			d.reportError(target, "routing target requires exactly one function")
			return nil
		}
		outbound = outbounds[0]
	}
	return &RoutingRule{AndFunctions: functions, Outbound: *outbound}
}

func (d *decoder) parseProxyReference(function *Function, annotation []*Param, ctx antlr.ParserRuleContext) *Param {
	if function == nil || function.Not || function.Quoted || len(function.Params) != 1 ||
		function.Params[0].Key != "" || strings.TrimSpace(function.Params[0].Val) == "" {
		d.reportError(ctx, "path reference must be node(name) or group(name)")
		return nil
	}
	switch function.Name {
	case "node":
	case "group":
	default:
		d.reportError(ctx, "path reference must be node(name) or group(name)")
		return nil
	}
	return &Param{AndFunctions: []*Function{function}, Annotation: annotation}
}

func (d *decoder) parseProxyPathStage(ctx dae_config.IArrowOperandContext) *Param {
	operand := ctx.(*dae_config.ArrowOperandContext)
	if operand.Literal() != nil {
		d.reportError(ctx, "literal proxy path stage")
		return nil
	}
	annotation := d.parseOptAnnotation(operand.OptAnnotation())
	functions := d.parseFunctions(operand.AllFunctionPrototype())
	if functions == nil {
		return nil
	}
	if key := operand.ID(); key != nil {
		if key.GetText() != "filter" {
			d.reportError(ctx, "proxy path declaration must be filter")
			return nil
		}
		return &Param{Key: "filter", AndFunctions: functions, Annotation: annotation}
	}
	if len(functions) != 1 {
		d.reportError(ctx, "proxy path reference requires exactly one function")
		return nil
	}
	return d.parseProxyReference(functions[0], annotation, ctx)
}

func (d *decoder) parseProxyPath(ctx dae_config.IArrowExpressionContext) *ProxyPath {
	path := new(ProxyPath)
	for _, operand := range ctx.(*dae_config.ArrowExpressionContext).AllArrowOperand() {
		stage := d.parseProxyPathStage(operand)
		if stage == nil {
			return nil
		}
		path.Stages = append(path.Stages, stage)
	}
	return path
}

func (d *decoder) parseStandaloneProxyPath(ctx dae_config.IStandaloneFunctionContext) *ProxyPath {
	reference := ctx.(*dae_config.StandaloneFunctionContext)
	function := d.parseFunctionPrototype(reference.FunctionPrototype().(*dae_config.FunctionPrototypeContext))
	stage := d.parseProxyReference(function, d.parseOptAnnotation(reference.OptAnnotation()), ctx)
	if stage == nil {
		return nil
	}
	return &ProxyPath{Stages: []*Param{stage}}
}

type statementKind uint8

const (
	configStatement statementKind = iota
	proxyPathStatement
)

func (d *decoder) parseStatements(ctx *dae_config.ExpressionContext, kind, childKind statementKind) (items []*Item) {
	for _, elem := range ctx.GetChildren() {
		switch elem := elem.(type) {
		case dae_config.IArrowExpressionContext:
			if kind == proxyPathStatement {
				path := d.parseProxyPath(elem)
				if path == nil {
					return items
				}
				items = append(items, newItem(path))
			} else {
				rule := d.parseRoutingRule(elem)
				if rule == nil {
					return items
				}
				items = append(items, newItem(rule))
			}
		case dae_config.IDeclarationContext:
			param := d.parseDeclaration(elem)
			if param == nil {
				return items
			}
			if kind == proxyPathStatement && param.Key == "filter" {
				if param.AndFunctions == nil {
					d.reportError(elem, "filter requires a function expression")
					return items
				}
				items = append(items, newItem(&ProxyPath{Stages: []*Param{param}}))
			} else {
				items = append(items, newItem(param))
			}
		case dae_config.IStandaloneFunctionContext:
			if kind != proxyPathStatement {
				d.reportError(elem, "proxy path reference outside a group definition")
				return items
			}
			path := d.parseStandaloneProxyPath(elem)
			if path == nil {
				return items
			}
			items = append(items, newItem(path))
		case *dae_config.LiteralContext:
			items = append(items, newItem(&Param{
				Key: "",
				Val: getValueFromLiteral(elem),
			}))
		case dae_config.IExpressionContext:
			section := d.parseExpression(elem, childKind, false)
			if section == nil {
				return items
			}
			items = append(items, newItem(section))
		case *antlr.TerminalNodeImpl:
		}
	}
	return items
}

func (d *decoder) parseExpression(exp dae_config.IExpressionContext, kind statementKind, topLevel bool) *Section {
	expression := exp.(*dae_config.ExpressionContext)
	name := expression.ID().GetText()
	childKind := configStatement
	if topLevel && name == "group" {
		childKind = proxyPathStatement
	}
	return &Section{
		Name:  name,
		Items: d.parseStatements(expression, kind, childKind),
	}
}

func (d *decoder) decode(start dae_config.IStartContext) (sections []*Section) {
	for _, expression := range start.(*dae_config.StartContext).AllExpression() {
		section := d.parseExpression(expression, configStatement, true)
		if section != nil {
			sections = append(sections, section)
		}
	}
	return sections
}
