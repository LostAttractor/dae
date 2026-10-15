// Code generated from dae_config.g4 by ANTLR 4.13.1. DO NOT EDIT.

package dae_config // dae_config
import "github.com/antlr4-go/antlr/v4"

// Basedae_configListener is a complete listener for a parse tree produced by dae_configParser.
type Basedae_configListener struct{}

var _ dae_configListener = &Basedae_configListener{}

// VisitTerminal is called when a terminal node is visited.
func (s *Basedae_configListener) VisitTerminal(node antlr.TerminalNode) {}

// VisitErrorNode is called when an error node is visited.
func (s *Basedae_configListener) VisitErrorNode(node antlr.ErrorNode) {}

// EnterEveryRule is called when any rule is entered.
func (s *Basedae_configListener) EnterEveryRule(ctx antlr.ParserRuleContext) {}

// ExitEveryRule is called when any rule is exited.
func (s *Basedae_configListener) ExitEveryRule(ctx antlr.ParserRuleContext) {}

// EnterStart is called when production start is entered.
func (s *Basedae_configListener) EnterStart(ctx *StartContext) {}

// ExitStart is called when production start is exited.
func (s *Basedae_configListener) ExitStart(ctx *StartContext) {}

// EnterLiteral is called when production literal is entered.
func (s *Basedae_configListener) EnterLiteral(ctx *LiteralContext) {}

// ExitLiteral is called when production literal is exited.
func (s *Basedae_configListener) ExitLiteral(ctx *LiteralContext) {}

// EnterExpression is called when production expression is entered.
func (s *Basedae_configListener) EnterExpression(ctx *ExpressionContext) {}

// ExitExpression is called when production expression is exited.
func (s *Basedae_configListener) ExitExpression(ctx *ExpressionContext) {}

// EnterDeclaration is called when production declaration is entered.
func (s *Basedae_configListener) EnterDeclaration(ctx *DeclarationContext) {}

// ExitDeclaration is called when production declaration is exited.
func (s *Basedae_configListener) ExitDeclaration(ctx *DeclarationContext) {}

// EnterOptAnnotation is called when production optAnnotation is entered.
func (s *Basedae_configListener) EnterOptAnnotation(ctx *OptAnnotationContext) {}

// ExitOptAnnotation is called when production optAnnotation is exited.
func (s *Basedae_configListener) ExitOptAnnotation(ctx *OptAnnotationContext) {}

// EnterAnnotationParameter is called when production annotationParameter is entered.
func (s *Basedae_configListener) EnterAnnotationParameter(ctx *AnnotationParameterContext) {}

// ExitAnnotationParameter is called when production annotationParameter is exited.
func (s *Basedae_configListener) ExitAnnotationParameter(ctx *AnnotationParameterContext) {}

// EnterFunctionPrototype is called when production functionPrototype is entered.
func (s *Basedae_configListener) EnterFunctionPrototype(ctx *FunctionPrototypeContext) {}

// ExitFunctionPrototype is called when production functionPrototype is exited.
func (s *Basedae_configListener) ExitFunctionPrototype(ctx *FunctionPrototypeContext) {}

// EnterParameter is called when production parameter is entered.
func (s *Basedae_configListener) EnterParameter(ctx *ParameterContext) {}

// ExitParameter is called when production parameter is exited.
func (s *Basedae_configListener) ExitParameter(ctx *ParameterContext) {}

// EnterArrowExpression is called when production arrowExpression is entered.
func (s *Basedae_configListener) EnterArrowExpression(ctx *ArrowExpressionContext) {}

// ExitArrowExpression is called when production arrowExpression is exited.
func (s *Basedae_configListener) ExitArrowExpression(ctx *ArrowExpressionContext) {}

// EnterArrowOperand is called when production arrowOperand is entered.
func (s *Basedae_configListener) EnterArrowOperand(ctx *ArrowOperandContext) {}

// ExitArrowOperand is called when production arrowOperand is exited.
func (s *Basedae_configListener) ExitArrowOperand(ctx *ArrowOperandContext) {}

// EnterStandaloneFunction is called when production standaloneFunction is entered.
func (s *Basedae_configListener) EnterStandaloneFunction(ctx *StandaloneFunctionContext) {}

// ExitStandaloneFunction is called when production standaloneFunction is exited.
func (s *Basedae_configListener) ExitStandaloneFunction(ctx *StandaloneFunctionContext) {}
