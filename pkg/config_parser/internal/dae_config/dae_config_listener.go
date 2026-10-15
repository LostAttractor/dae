// Code generated from dae_config.g4 by ANTLR 4.13.1. DO NOT EDIT.

package dae_config // dae_config
import "github.com/antlr4-go/antlr/v4"

// dae_configListener is a complete listener for a parse tree produced by dae_configParser.
type dae_configListener interface {
	antlr.ParseTreeListener

	// EnterStart is called when entering the start production.
	EnterStart(c *StartContext)

	// EnterLiteral is called when entering the literal production.
	EnterLiteral(c *LiteralContext)

	// EnterExpression is called when entering the expression production.
	EnterExpression(c *ExpressionContext)

	// EnterDeclaration is called when entering the declaration production.
	EnterDeclaration(c *DeclarationContext)

	// EnterOptAnnotation is called when entering the optAnnotation production.
	EnterOptAnnotation(c *OptAnnotationContext)

	// EnterAnnotationParameter is called when entering the annotationParameter production.
	EnterAnnotationParameter(c *AnnotationParameterContext)

	// EnterFunctionPrototype is called when entering the functionPrototype production.
	EnterFunctionPrototype(c *FunctionPrototypeContext)

	// EnterParameter is called when entering the parameter production.
	EnterParameter(c *ParameterContext)

	// EnterArrowExpression is called when entering the arrowExpression production.
	EnterArrowExpression(c *ArrowExpressionContext)

	// EnterArrowOperand is called when entering the arrowOperand production.
	EnterArrowOperand(c *ArrowOperandContext)

	// EnterStandaloneFunction is called when entering the standaloneFunction production.
	EnterStandaloneFunction(c *StandaloneFunctionContext)

	// ExitStart is called when exiting the start production.
	ExitStart(c *StartContext)

	// ExitLiteral is called when exiting the literal production.
	ExitLiteral(c *LiteralContext)

	// ExitExpression is called when exiting the expression production.
	ExitExpression(c *ExpressionContext)

	// ExitDeclaration is called when exiting the declaration production.
	ExitDeclaration(c *DeclarationContext)

	// ExitOptAnnotation is called when exiting the optAnnotation production.
	ExitOptAnnotation(c *OptAnnotationContext)

	// ExitAnnotationParameter is called when exiting the annotationParameter production.
	ExitAnnotationParameter(c *AnnotationParameterContext)

	// ExitFunctionPrototype is called when exiting the functionPrototype production.
	ExitFunctionPrototype(c *FunctionPrototypeContext)

	// ExitParameter is called when exiting the parameter production.
	ExitParameter(c *ParameterContext)

	// ExitArrowExpression is called when exiting the arrowExpression production.
	ExitArrowExpression(c *ArrowExpressionContext)

	// ExitArrowOperand is called when exiting the arrowOperand production.
	ExitArrowOperand(c *ArrowOperandContext)

	// ExitStandaloneFunction is called when exiting the standaloneFunction production.
	ExitStandaloneFunction(c *StandaloneFunctionContext)
}
