// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"fmt"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
	"github.com/dop251/goja/token"
)

// scriptUsesPersistentStore proves a direct API call exists, not that it is reachable.
// shortcut: aliases and dynamic/global-object access are not resolved; extend only when required.
func scriptUsesPersistentStore(source string) (bool, error) {
	program, err := parser.ParseFile(nil, "", source, 0, parser.WithDisableSourceMaps)
	if err != nil {
		return false, err
	}
	d := storeDetection{source: source}
	// Global var declarations reuse the host binding; initializers count as writes.
	scope := newStoreScope(nil, nil)
	scope.strict = d.strictBody(program.Body, 0)
	d.statements(program.Body, scope)
	if d.err != nil || d.uncertain {
		return false, d.err
	}
	for _, block := range d.annex {
		scope := block.parent
		for scope != block.hoist && (!scope.bound || scope.catchVar) {
			scope = scope.parent
		}
		if scope == block.hoist {
			scope.bound = true
		}
	}
	for _, scope := range d.writes {
		if scope.unbound() {
			return false, nil
		}
	}
	for _, scope := range d.calls {
		if scope.unbound() {
			return true, nil
		}
	}
	return false, nil
}

// Only the target name is tracked; deferred lookup also covers declarations after calls.
type storeScope struct {
	parent, hoist                     *storeScope
	bound, strict, catchVar, resolved bool
}

func newStoreScope(parent *storeScope, declarations []*ast.VariableDeclaration) *storeScope {
	s := &storeScope{parent: parent}
	if parent != nil {
		s.strict = parent.strict
	}
	s.hoist = s
	for _, declaration := range declarations {
		s.bind(declaration.List)
	}
	return s
}

func (s *storeScope) block() *storeScope {
	return &storeScope{parent: s, hoist: s.hoist, strict: s.strict}
}

func (s *storeScope) bind(bindings []*ast.Binding) {
	for _, binding := range bindings {
		s.bound = s.bound || storeTarget(binding.Target, false)
	}
}

func (s *storeScope) unbound() bool {
	// Called only after all bindings are collected; cache shared ancestor lookups.
	if !s.resolved {
		if s.parent != nil {
			s.bound = s.bound || !s.parent.unbound()
		}
		s.resolved = true
	}
	return !s.bound
}

func (d *storeDetection) strictBody(body []ast.Statement, start int) bool {
	for _, statement := range body {
		expression, ok := statement.(*ast.ExpressionStatement)
		if !ok {
			break
		}
		literal, ok := expression.Expression.(*ast.StringLiteral)
		if !ok {
			break
		}
		// The AST drops parentheses; an unfinished parenthesized string is not a directive.
		end := int(literal.Idx1()) - 1
		if _, err := parser.ParseFile(nil, "", d.source[start:end], 0, parser.WithDisableSourceMaps); err != nil {
			break
		}
		start = end
		if literal.Literal == `"use strict"` || literal.Literal == `'use strict'` {
			return true
		}
	}
	return false
}

func storeUnwrap(expression ast.Expression) ast.Expression {
	for {
		switch n := expression.(type) {
		case *ast.Optional:
			expression = n.Expression
		case *ast.OptionalChain:
			expression = n.Expression
		default:
			return expression
		}
	}
}

func storeMember(expression ast.Expression) (ast.Expression, string) {
	switch n := storeUnwrap(expression).(type) {
	case *ast.DotExpression:
		return n.Left, n.Identifier.Name.String()
	case *ast.BracketExpression:
		if key, ok := n.Member.(*ast.StringLiteral); ok {
			return n.Left, key.Value.String()
		}
	}
	return nil, ""
}

// Binding patterns and assignment targets share structure, but only writes include members.
func storeTarget(expression ast.Expression, members bool) bool {
	switch n := storeUnwrap(expression).(type) {
	case *ast.Identifier:
		return n.Name == "$persistentStore"
	case *ast.Binding:
		return storeTarget(n.Target, members)
	case *ast.AssignExpression:
		return storeTarget(n.Left, members)
	case *ast.ArrayPattern:
		for _, element := range n.Elements {
			if storeTarget(element, members) {
				return true
			}
		}
		return storeTarget(n.Rest, members)
	case *ast.ObjectPattern:
		for _, property := range n.Properties {
			if storeTarget(property, members) {
				return true
			}
		}
		return storeTarget(n.Rest, members)
	case *ast.PropertyShort:
		return n.Name.Name == "$persistentStore"
	case *ast.PropertyKeyed:
		return storeTarget(n.Value, members)
	case *ast.SpreadElement:
		return storeTarget(n.Expression, members)
	case *ast.DotExpression:
		return members && storeTarget(n.Left, true)
	case *ast.BracketExpression:
		return members && storeTarget(n.Left, true)
	}
	return false
}

type storeDetection struct {
	source        string
	calls, writes []*storeScope
	annex         []*storeScope
	uncertain     bool
	err           error
}

func (d *storeDetection) statements(body []ast.Statement, scope *storeScope) {
	for _, statement := range body {
		d.walk(statement, scope)
	}
}

func (d *storeDetection) bindings(bindings []*ast.Binding, scope *storeScope) {
	for _, binding := range bindings {
		d.walk(binding, scope)
	}
}

func (d *storeDetection) expressions(expressions []ast.Expression, scope *storeScope) {
	for _, expression := range expressions {
		d.walk(expression, scope)
	}
}

func (d *storeDetection) function(name *ast.Identifier, params *ast.ParameterList, body ast.ConciseBody, declarations []*ast.VariableDeclaration, parent *storeScope) {
	scope := newStoreScope(parent, nil)
	if block, ok := body.(*ast.BlockStatement); ok {
		scope.strict = scope.strict || d.strictBody(block.List, int(block.LeftBrace))
	}
	if name != nil {
		scope.bound = storeTarget(name, false)
	}
	scope.bind(params.List)
	scope.bound = scope.bound || storeTarget(params.Rest, false)
	d.bindings(params.List, scope)
	d.walk(params.Rest, scope)
	// Body var/lexical bindings are not visible in parameter initializers.
	scope = newStoreScope(scope, declarations)
	if block, ok := body.(*ast.BlockStatement); ok {
		d.statements(block.List, scope)
	} else {
		d.walk(body, scope)
	}
}

func (d *storeDetection) write(target ast.Expression, scope *storeScope) {
	if storeTarget(target, true) {
		d.writes = append(d.writes, scope)
	}
}

// goja has no AST visitor; keep child traversal and scope changes in this one dispatch.
func (d *storeDetection) walk(node ast.Node, scope *storeScope) {
	if node == nil || d.err != nil {
		return
	}
	switch n := node.(type) {
	case *ast.BlockStatement:
		d.statements(n.List, scope.block())
	case *ast.ExpressionStatement:
		d.walk(n.Expression, scope)
	case *ast.ExpressionBody:
		d.walk(n.Expression, scope)
	case *ast.FunctionDeclaration:
		if storeTarget(n.Function.Name, false) {
			scope.bound = true
			// Annex B hoisting depends on intervening lexical declarations, including later ones.
			if scope != scope.hoist && !scope.strict && !n.Function.Async && !n.Function.Generator {
				d.annex = append(d.annex, scope)
			}
		}
		d.walk(n.Function, scope)
	case *ast.FunctionLiteral:
		d.function(n.Name, n.ParameterList, n.Body, n.DeclarationList, scope)
	case *ast.ArrowFunctionLiteral:
		d.function(nil, n.ParameterList, n.Body, n.DeclarationList, scope)
	case *ast.ClassDeclaration:
		scope.bound = scope.bound || storeTarget(n.Class.Name, false)
		d.walk(n.Class, scope)
	case *ast.ClassLiteral:
		scope = scope.block()
		scope.strict = true
		if n.Name != nil {
			scope.bound = storeTarget(n.Name, false)
		}
		d.walk(n.SuperClass, scope)
		for _, element := range n.Body {
			d.walk(element, scope)
		}
	case *ast.FieldDefinition:
		if n.Computed {
			d.walk(n.Key, scope)
		}
		d.walk(n.Initializer, scope)
	case *ast.MethodDefinition:
		if n.Computed {
			d.walk(n.Key, scope)
		}
		d.walk(n.Body, scope)
	case *ast.ClassStaticBlock:
		d.statements(n.Block.List, newStoreScope(scope, n.DeclarationList))
	case *ast.VariableStatement:
		d.bindings(n.List, scope)
	case *ast.LexicalDeclaration:
		scope.bind(n.List)
		d.bindings(n.List, scope)
	case *ast.Binding:
		if n.Initializer != nil {
			d.write(n.Target, scope)
		}
		d.walk(n.Target, scope)
		d.walk(n.Initializer, scope)
	case *ast.CatchStatement:
		scope = scope.block()
		scope.bound = storeTarget(n.Parameter, false)
		// A simple catch parameter permits Annex B var redeclarations; a pattern does not.
		_, scope.catchVar = n.Parameter.(*ast.Identifier)
		d.walk(n.Parameter, scope)
		d.walk(n.Body, scope)
	case *ast.TryStatement:
		d.walk(n.Body, scope)
		if n.Catch != nil {
			d.walk(n.Catch, scope)
		}
		if n.Finally != nil {
			d.walk(n.Finally, scope)
		}
	case *ast.ForStatement:
		scope = scope.block()
		d.walk(n.Initializer, scope)
		d.walk(n.Test, scope)
		d.walk(n.Update, scope)
		d.walk(n.Body, scope)
	case *ast.ForInStatement:
		scope = scope.block()
		d.walk(n.Into, scope)
		d.walk(n.Source, scope)
		d.walk(n.Body, scope)
	case *ast.ForOfStatement:
		scope = scope.block()
		d.walk(n.Into, scope)
		d.walk(n.Source, scope)
		d.walk(n.Body, scope)
	case *ast.ForLoopInitializerExpression:
		d.walk(n.Expression, scope)
	case *ast.ForLoopInitializerVarDeclList:
		d.bindings(n.List, scope)
	case *ast.ForLoopInitializerLexicalDecl:
		d.walk(&n.LexicalDeclaration, scope)
	case *ast.ForIntoVar:
		d.write(n.Binding.Target, scope)
		d.walk(n.Binding, scope)
	case *ast.ForDeclaration:
		scope.bound = scope.bound || storeTarget(n.Target, false)
		d.walk(n.Target, scope)
	case *ast.ForIntoExpression:
		d.write(n.Expression, scope)
		d.walk(n.Expression, scope)
	case *ast.SwitchStatement:
		d.walk(n.Discriminant, scope)
		scope = scope.block()
		for _, clause := range n.Body {
			d.walk(clause, scope)
		}
	case *ast.CaseStatement:
		d.walk(n.Test, scope)
		d.statements(n.Consequent, scope)
	case *ast.IfStatement:
		d.walk(n.Test, scope)
		d.walk(n.Consequent, scope)
		d.walk(n.Alternate, scope)
	case *ast.WhileStatement:
		d.walk(n.Test, scope)
		d.walk(n.Body, scope)
	case *ast.DoWhileStatement:
		d.walk(n.Body, scope)
		d.walk(n.Test, scope)
	case *ast.LabelledStatement:
		d.walk(n.Statement, scope)
	case *ast.ReturnStatement:
		d.walk(n.Argument, scope)
	case *ast.ThrowStatement:
		d.walk(n.Argument, scope)
	case *ast.WithStatement:
		d.uncertain = true
	case *ast.CallExpression:
		base, method := storeMember(n.Callee)
		if (method == "read" || method == "write") && storeTarget(base, false) {
			d.calls = append(d.calls, scope)
		}
		if len(n.ArgumentList) > 0 {
			if object, ok := storeUnwrap(base).(*ast.Identifier); ok {
				switch object.Name {
				case "Object", "Reflect":
					switch method {
					case "assign", "defineProperty", "defineProperties", "set", "deleteProperty", "setPrototypeOf":
						d.write(n.ArgumentList[0], scope)
					}
				}
			}
		}
		if method == "__defineGetter__" || method == "__defineSetter__" {
			d.write(base, scope)
		}
		d.walk(n.Callee, scope)
		d.expressions(n.ArgumentList, scope)
	case *ast.NewExpression:
		d.walk(n.Callee, scope)
		d.expressions(n.ArgumentList, scope)
	case *ast.AssignExpression:
		d.write(n.Left, scope)
		d.walk(n.Left, scope)
		d.walk(n.Right, scope)
	case *ast.UnaryExpression:
		if n.Operator == token.DELETE || n.Operator == token.INCREMENT || n.Operator == token.DECREMENT {
			d.write(n.Operand, scope)
		}
		d.walk(n.Operand, scope)
	case *ast.BinaryExpression:
		d.walk(n.Left, scope)
		d.walk(n.Right, scope)
	case *ast.ConditionalExpression:
		d.walk(n.Test, scope)
		d.walk(n.Consequent, scope)
		d.walk(n.Alternate, scope)
	case *ast.DotExpression:
		if n.Identifier.Name == "eval" {
			d.uncertain = true
		}
		d.walk(n.Left, scope)
	case *ast.BracketExpression:
		if _, member := storeMember(n); member == "eval" {
			d.uncertain = true
		}
		d.walk(n.Left, scope)
		d.walk(n.Member, scope)
	case *ast.PrivateDotExpression:
		d.walk(n.Left, scope)
	case *ast.Optional:
		d.walk(n.Expression, scope)
	case *ast.OptionalChain:
		d.walk(n.Expression, scope)
	case *ast.ArrayLiteral:
		d.expressions(n.Value, scope)
	case *ast.ArrayPattern:
		d.expressions(n.Elements, scope)
		d.walk(n.Rest, scope)
	case *ast.ObjectLiteral:
		for _, property := range n.Value {
			d.walk(property, scope)
		}
	case *ast.ObjectPattern:
		for _, property := range n.Properties {
			d.walk(property, scope)
		}
		d.walk(n.Rest, scope)
	case *ast.PropertyShort:
		d.walk(n.Initializer, scope)
	case *ast.PropertyKeyed:
		if n.Computed {
			d.walk(n.Key, scope)
		}
		d.walk(n.Value, scope)
	case *ast.SpreadElement:
		d.walk(n.Expression, scope)
	case *ast.SequenceExpression:
		d.expressions(n.Sequence, scope)
	case *ast.TemplateLiteral:
		d.walk(n.Tag, scope)
		d.expressions(n.Expressions, scope)
	case *ast.AwaitExpression:
		d.walk(n.Argument, scope)
	case *ast.YieldExpression:
		d.walk(n.Argument, scope)
	case *ast.Identifier:
		if n.Name == "eval" {
			d.uncertain = true
		}
	case *ast.BooleanLiteral, *ast.NullLiteral, *ast.NumberLiteral, *ast.StringLiteral,
		*ast.RegExpLiteral, *ast.ThisExpression, *ast.SuperExpression, *ast.MetaProperty,
		*ast.PrivateIdentifier, *ast.EmptyStatement, *ast.BranchStatement, *ast.DebuggerStatement:
	default:
		d.err = fmt.Errorf("unsupported JavaScript storage detection node %T", node)
	}
}
