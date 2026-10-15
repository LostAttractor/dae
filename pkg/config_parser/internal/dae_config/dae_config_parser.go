// Code generated from dae_config.g4 by ANTLR 4.13.1. DO NOT EDIT.

package dae_config // dae_config
import (
	"fmt"
	"strconv"
	"sync"

	"github.com/antlr4-go/antlr/v4"
)

// Suppress unused import errors
var _ = fmt.Printf
var _ = strconv.Itoa
var _ = sync.Once{}

type dae_configParser struct {
	*antlr.BaseParser
}

var Dae_configParserStaticData struct {
	once                   sync.Once
	serializedATN          []int32
	LiteralNames           []string
	SymbolicNames          []string
	RuleNames              []string
	PredictionContextCache *antlr.PredictionContextCache
	atn                    *antlr.ATN
	decisionToDFA          []*antlr.DFA
}

func dae_configParserInit() {
	staticData := &Dae_configParserStaticData
	staticData.LiteralNames = []string{
		"", "'{'", "'}'", "':'", "'&&'", "','", "'['", "']'", "'!'", "'('",
		"')'", "'->'",
	}
	staticData.SymbolicNames = []string{
		"", "", "", "", "", "", "", "", "", "", "", "", "WHITESPACE", "COMMENT_BLOCK",
		"COMMENT_LINE_SHARP", "ID", "NON_ID", "QUOTE_STRING",
	}
	staticData.RuleNames = []string{
		"start", "literal", "expression", "declaration", "optAnnotation", "annotationParameter",
		"functionPrototype", "parameter", "arrowExpression", "arrowOperand",
		"standaloneFunction",
	}
	staticData.PredictionContextCache = antlr.NewPredictionContextCache()
	staticData.serializedATN = []int32{
		4, 1, 17, 155, 2, 0, 7, 0, 2, 1, 7, 1, 2, 2, 7, 2, 2, 3, 7, 3, 2, 4, 7,
		4, 2, 5, 7, 5, 2, 6, 7, 6, 2, 7, 7, 7, 2, 8, 7, 8, 2, 9, 7, 9, 2, 10, 7,
		10, 1, 0, 5, 0, 24, 8, 0, 10, 0, 12, 0, 27, 9, 0, 1, 0, 1, 0, 1, 1, 1,
		1, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 5, 2, 40, 8, 2, 10, 2, 12,
		2, 43, 9, 2, 1, 2, 1, 2, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 5, 3, 52, 8, 3,
		10, 3, 12, 3, 55, 9, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 5, 3,
		64, 8, 3, 10, 3, 12, 3, 67, 9, 3, 1, 3, 1, 3, 3, 3, 71, 8, 3, 1, 4, 1,
		4, 1, 4, 1, 4, 5, 4, 77, 8, 4, 10, 4, 12, 4, 80, 9, 4, 3, 4, 82, 8, 4,
		1, 4, 1, 4, 3, 4, 86, 8, 4, 1, 5, 1, 5, 1, 5, 1, 5, 3, 5, 92, 8, 5, 1,
		6, 3, 6, 95, 8, 6, 1, 6, 1, 6, 1, 6, 1, 6, 1, 6, 5, 6, 102, 8, 6, 10, 6,
		12, 6, 105, 9, 6, 3, 6, 107, 8, 6, 1, 6, 1, 6, 1, 7, 1, 7, 1, 7, 1, 7,
		3, 7, 115, 8, 7, 1, 8, 1, 8, 1, 8, 1, 8, 1, 8, 5, 8, 122, 8, 8, 10, 8,
		12, 8, 125, 9, 8, 1, 9, 1, 9, 1, 9, 1, 9, 1, 9, 5, 9, 132, 8, 9, 10, 9,
		12, 9, 135, 9, 9, 1, 9, 1, 9, 1, 9, 1, 9, 1, 9, 5, 9, 142, 8, 9, 10, 9,
		12, 9, 145, 9, 9, 1, 9, 1, 9, 1, 9, 3, 9, 150, 8, 9, 1, 10, 1, 10, 1, 10,
		1, 10, 0, 0, 11, 0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 0, 1, 1, 0, 15,
		17, 165, 0, 25, 1, 0, 0, 0, 2, 30, 1, 0, 0, 0, 4, 32, 1, 0, 0, 0, 6, 70,
		1, 0, 0, 0, 8, 85, 1, 0, 0, 0, 10, 91, 1, 0, 0, 0, 12, 94, 1, 0, 0, 0,
		14, 114, 1, 0, 0, 0, 16, 116, 1, 0, 0, 0, 18, 149, 1, 0, 0, 0, 20, 151,
		1, 0, 0, 0, 22, 24, 3, 4, 2, 0, 23, 22, 1, 0, 0, 0, 24, 27, 1, 0, 0, 0,
		25, 23, 1, 0, 0, 0, 25, 26, 1, 0, 0, 0, 26, 28, 1, 0, 0, 0, 27, 25, 1,
		0, 0, 0, 28, 29, 5, 0, 0, 1, 29, 1, 1, 0, 0, 0, 30, 31, 7, 0, 0, 0, 31,
		3, 1, 0, 0, 0, 32, 33, 5, 15, 0, 0, 33, 41, 5, 1, 0, 0, 34, 40, 3, 16,
		8, 0, 35, 40, 3, 6, 3, 0, 36, 40, 3, 20, 10, 0, 37, 40, 3, 2, 1, 0, 38,
		40, 3, 4, 2, 0, 39, 34, 1, 0, 0, 0, 39, 35, 1, 0, 0, 0, 39, 36, 1, 0, 0,
		0, 39, 37, 1, 0, 0, 0, 39, 38, 1, 0, 0, 0, 40, 43, 1, 0, 0, 0, 41, 39,
		1, 0, 0, 0, 41, 42, 1, 0, 0, 0, 42, 44, 1, 0, 0, 0, 43, 41, 1, 0, 0, 0,
		44, 45, 5, 2, 0, 0, 45, 5, 1, 0, 0, 0, 46, 47, 7, 0, 0, 0, 47, 48, 5, 3,
		0, 0, 48, 53, 3, 12, 6, 0, 49, 50, 5, 4, 0, 0, 50, 52, 3, 12, 6, 0, 51,
		49, 1, 0, 0, 0, 52, 55, 1, 0, 0, 0, 53, 51, 1, 0, 0, 0, 53, 54, 1, 0, 0,
		0, 54, 56, 1, 0, 0, 0, 55, 53, 1, 0, 0, 0, 56, 57, 3, 8, 4, 0, 57, 71,
		1, 0, 0, 0, 58, 59, 7, 0, 0, 0, 59, 60, 5, 3, 0, 0, 60, 65, 3, 2, 1, 0,
		61, 62, 5, 5, 0, 0, 62, 64, 3, 2, 1, 0, 63, 61, 1, 0, 0, 0, 64, 67, 1,
		0, 0, 0, 65, 63, 1, 0, 0, 0, 65, 66, 1, 0, 0, 0, 66, 68, 1, 0, 0, 0, 67,
		65, 1, 0, 0, 0, 68, 69, 3, 8, 4, 0, 69, 71, 1, 0, 0, 0, 70, 46, 1, 0, 0,
		0, 70, 58, 1, 0, 0, 0, 71, 7, 1, 0, 0, 0, 72, 81, 5, 6, 0, 0, 73, 78, 3,
		10, 5, 0, 74, 75, 5, 5, 0, 0, 75, 77, 3, 10, 5, 0, 76, 74, 1, 0, 0, 0,
		77, 80, 1, 0, 0, 0, 78, 76, 1, 0, 0, 0, 78, 79, 1, 0, 0, 0, 79, 82, 1,
		0, 0, 0, 80, 78, 1, 0, 0, 0, 81, 73, 1, 0, 0, 0, 81, 82, 1, 0, 0, 0, 82,
		83, 1, 0, 0, 0, 83, 86, 5, 7, 0, 0, 84, 86, 1, 0, 0, 0, 85, 72, 1, 0, 0,
		0, 85, 84, 1, 0, 0, 0, 86, 9, 1, 0, 0, 0, 87, 92, 3, 14, 7, 0, 88, 89,
		5, 15, 0, 0, 89, 90, 5, 3, 0, 0, 90, 92, 3, 12, 6, 0, 91, 87, 1, 0, 0,
		0, 91, 88, 1, 0, 0, 0, 92, 11, 1, 0, 0, 0, 93, 95, 5, 8, 0, 0, 94, 93,
		1, 0, 0, 0, 94, 95, 1, 0, 0, 0, 95, 96, 1, 0, 0, 0, 96, 97, 7, 0, 0, 0,
		97, 106, 5, 9, 0, 0, 98, 103, 3, 14, 7, 0, 99, 100, 5, 5, 0, 0, 100, 102,
		3, 14, 7, 0, 101, 99, 1, 0, 0, 0, 102, 105, 1, 0, 0, 0, 103, 101, 1, 0,
		0, 0, 103, 104, 1, 0, 0, 0, 104, 107, 1, 0, 0, 0, 105, 103, 1, 0, 0, 0,
		106, 98, 1, 0, 0, 0, 106, 107, 1, 0, 0, 0, 107, 108, 1, 0, 0, 0, 108, 109,
		5, 10, 0, 0, 109, 13, 1, 0, 0, 0, 110, 111, 5, 15, 0, 0, 111, 112, 5, 3,
		0, 0, 112, 115, 3, 2, 1, 0, 113, 115, 3, 2, 1, 0, 114, 110, 1, 0, 0, 0,
		114, 113, 1, 0, 0, 0, 115, 15, 1, 0, 0, 0, 116, 117, 3, 18, 9, 0, 117,
		118, 5, 11, 0, 0, 118, 123, 3, 18, 9, 0, 119, 120, 5, 11, 0, 0, 120, 122,
		3, 18, 9, 0, 121, 119, 1, 0, 0, 0, 122, 125, 1, 0, 0, 0, 123, 121, 1, 0,
		0, 0, 123, 124, 1, 0, 0, 0, 124, 17, 1, 0, 0, 0, 125, 123, 1, 0, 0, 0,
		126, 127, 5, 15, 0, 0, 127, 128, 5, 3, 0, 0, 128, 133, 3, 12, 6, 0, 129,
		130, 5, 4, 0, 0, 130, 132, 3, 12, 6, 0, 131, 129, 1, 0, 0, 0, 132, 135,
		1, 0, 0, 0, 133, 131, 1, 0, 0, 0, 133, 134, 1, 0, 0, 0, 134, 136, 1, 0,
		0, 0, 135, 133, 1, 0, 0, 0, 136, 137, 3, 8, 4, 0, 137, 150, 1, 0, 0, 0,
		138, 143, 3, 12, 6, 0, 139, 140, 5, 4, 0, 0, 140, 142, 3, 12, 6, 0, 141,
		139, 1, 0, 0, 0, 142, 145, 1, 0, 0, 0, 143, 141, 1, 0, 0, 0, 143, 144,
		1, 0, 0, 0, 144, 146, 1, 0, 0, 0, 145, 143, 1, 0, 0, 0, 146, 147, 3, 8,
		4, 0, 147, 150, 1, 0, 0, 0, 148, 150, 3, 2, 1, 0, 149, 126, 1, 0, 0, 0,
		149, 138, 1, 0, 0, 0, 149, 148, 1, 0, 0, 0, 150, 19, 1, 0, 0, 0, 151, 152,
		3, 12, 6, 0, 152, 153, 3, 8, 4, 0, 153, 21, 1, 0, 0, 0, 18, 25, 39, 41,
		53, 65, 70, 78, 81, 85, 91, 94, 103, 106, 114, 123, 133, 143, 149,
	}
	deserializer := antlr.NewATNDeserializer(nil)
	staticData.atn = deserializer.Deserialize(staticData.serializedATN)
	atn := staticData.atn
	staticData.decisionToDFA = make([]*antlr.DFA, len(atn.DecisionToState))
	decisionToDFA := staticData.decisionToDFA
	for index, state := range atn.DecisionToState {
		decisionToDFA[index] = antlr.NewDFA(state, index)
	}
}

// dae_configParserInit initializes any static state used to implement dae_configParser. By default the
// static state used to implement the parser is lazily initialized during the first call to
// Newdae_configParser(). You can call this function if you wish to initialize the static state ahead
// of time.
func Dae_configParserInit() {
	staticData := &Dae_configParserStaticData
	staticData.once.Do(dae_configParserInit)
}

// Newdae_configParser produces a new parser instance for the optional input antlr.TokenStream.
func Newdae_configParser(input antlr.TokenStream) *dae_configParser {
	Dae_configParserInit()
	this := new(dae_configParser)
	this.BaseParser = antlr.NewBaseParser(input)
	staticData := &Dae_configParserStaticData
	this.Interpreter = antlr.NewParserATNSimulator(this, staticData.atn, staticData.decisionToDFA, staticData.PredictionContextCache)
	this.RuleNames = staticData.RuleNames
	this.LiteralNames = staticData.LiteralNames
	this.SymbolicNames = staticData.SymbolicNames
	this.GrammarFileName = "dae_config.g4"

	return this
}

// dae_configParser tokens.
const (
	dae_configParserEOF                = antlr.TokenEOF
	dae_configParserT__0               = 1
	dae_configParserT__1               = 2
	dae_configParserT__2               = 3
	dae_configParserT__3               = 4
	dae_configParserT__4               = 5
	dae_configParserT__5               = 6
	dae_configParserT__6               = 7
	dae_configParserT__7               = 8
	dae_configParserT__8               = 9
	dae_configParserT__9               = 10
	dae_configParserT__10              = 11
	dae_configParserWHITESPACE         = 12
	dae_configParserCOMMENT_BLOCK      = 13
	dae_configParserCOMMENT_LINE_SHARP = 14
	dae_configParserID                 = 15
	dae_configParserNON_ID             = 16
	dae_configParserQUOTE_STRING       = 17
)

// dae_configParser rules.
const (
	dae_configParserRULE_start               = 0
	dae_configParserRULE_literal             = 1
	dae_configParserRULE_expression          = 2
	dae_configParserRULE_declaration         = 3
	dae_configParserRULE_optAnnotation       = 4
	dae_configParserRULE_annotationParameter = 5
	dae_configParserRULE_functionPrototype   = 6
	dae_configParserRULE_parameter           = 7
	dae_configParserRULE_arrowExpression     = 8
	dae_configParserRULE_arrowOperand        = 9
	dae_configParserRULE_standaloneFunction  = 10
)

// IStartContext is an interface to support dynamic dispatch.
type IStartContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	EOF() antlr.TerminalNode
	AllExpression() []IExpressionContext
	Expression(i int) IExpressionContext

	// IsStartContext differentiates from other interfaces.
	IsStartContext()
}

type StartContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyStartContext() *StartContext {
	var p = new(StartContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_start
	return p
}

func InitEmptyStartContext(p *StartContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_start
}

func (*StartContext) IsStartContext() {}

func NewStartContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *StartContext {
	var p = new(StartContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_start

	return p
}

func (s *StartContext) GetParser() antlr.Parser { return s.parser }

func (s *StartContext) EOF() antlr.TerminalNode {
	return s.GetToken(dae_configParserEOF, 0)
}

func (s *StartContext) AllExpression() []IExpressionContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IExpressionContext); ok {
			len++
		}
	}

	tst := make([]IExpressionContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IExpressionContext); ok {
			tst[i] = t.(IExpressionContext)
			i++
		}
	}

	return tst
}

func (s *StartContext) Expression(i int) IExpressionContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpressionContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpressionContext)
}

func (s *StartContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *StartContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *StartContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterStart(s)
	}
}

func (s *StartContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitStart(s)
	}
}

func (p *dae_configParser) Start_() (localctx IStartContext) {
	localctx = NewStartContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 0, dae_configParserRULE_start)
	var _la int

	p.EnterOuterAlt(localctx, 1)
	p.SetState(25)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_la = p.GetTokenStream().LA(1)

	for _la == dae_configParserID {
		{
			p.SetState(22)
			p.Expression()
		}

		p.SetState(27)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)
	}
	{
		p.SetState(28)
		p.Match(dae_configParserEOF)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// ILiteralContext is an interface to support dynamic dispatch.
type ILiteralContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	ID() antlr.TerminalNode
	NON_ID() antlr.TerminalNode
	QUOTE_STRING() antlr.TerminalNode

	// IsLiteralContext differentiates from other interfaces.
	IsLiteralContext()
}

type LiteralContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyLiteralContext() *LiteralContext {
	var p = new(LiteralContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_literal
	return p
}

func InitEmptyLiteralContext(p *LiteralContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_literal
}

func (*LiteralContext) IsLiteralContext() {}

func NewLiteralContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *LiteralContext {
	var p = new(LiteralContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_literal

	return p
}

func (s *LiteralContext) GetParser() antlr.Parser { return s.parser }

func (s *LiteralContext) ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserID, 0)
}

func (s *LiteralContext) NON_ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserNON_ID, 0)
}

func (s *LiteralContext) QUOTE_STRING() antlr.TerminalNode {
	return s.GetToken(dae_configParserQUOTE_STRING, 0)
}

func (s *LiteralContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *LiteralContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *LiteralContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterLiteral(s)
	}
}

func (s *LiteralContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitLiteral(s)
	}
}

func (p *dae_configParser) Literal() (localctx ILiteralContext) {
	localctx = NewLiteralContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 2, dae_configParserRULE_literal)
	var _la int

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(30)
		_la = p.GetTokenStream().LA(1)

		if !((int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&229376) != 0) {
			p.GetErrorHandler().RecoverInline(p)
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// IExpressionContext is an interface to support dynamic dispatch.
type IExpressionContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	ID() antlr.TerminalNode
	AllArrowExpression() []IArrowExpressionContext
	ArrowExpression(i int) IArrowExpressionContext
	AllDeclaration() []IDeclarationContext
	Declaration(i int) IDeclarationContext
	AllStandaloneFunction() []IStandaloneFunctionContext
	StandaloneFunction(i int) IStandaloneFunctionContext
	AllLiteral() []ILiteralContext
	Literal(i int) ILiteralContext
	AllExpression() []IExpressionContext
	Expression(i int) IExpressionContext

	// IsExpressionContext differentiates from other interfaces.
	IsExpressionContext()
}

type ExpressionContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyExpressionContext() *ExpressionContext {
	var p = new(ExpressionContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_expression
	return p
}

func InitEmptyExpressionContext(p *ExpressionContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_expression
}

func (*ExpressionContext) IsExpressionContext() {}

func NewExpressionContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ExpressionContext {
	var p = new(ExpressionContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_expression

	return p
}

func (s *ExpressionContext) GetParser() antlr.Parser { return s.parser }

func (s *ExpressionContext) ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserID, 0)
}

func (s *ExpressionContext) AllArrowExpression() []IArrowExpressionContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IArrowExpressionContext); ok {
			len++
		}
	}

	tst := make([]IArrowExpressionContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IArrowExpressionContext); ok {
			tst[i] = t.(IArrowExpressionContext)
			i++
		}
	}

	return tst
}

func (s *ExpressionContext) ArrowExpression(i int) IArrowExpressionContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IArrowExpressionContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IArrowExpressionContext)
}

func (s *ExpressionContext) AllDeclaration() []IDeclarationContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IDeclarationContext); ok {
			len++
		}
	}

	tst := make([]IDeclarationContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IDeclarationContext); ok {
			tst[i] = t.(IDeclarationContext)
			i++
		}
	}

	return tst
}

func (s *ExpressionContext) Declaration(i int) IDeclarationContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IDeclarationContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IDeclarationContext)
}

func (s *ExpressionContext) AllStandaloneFunction() []IStandaloneFunctionContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IStandaloneFunctionContext); ok {
			len++
		}
	}

	tst := make([]IStandaloneFunctionContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IStandaloneFunctionContext); ok {
			tst[i] = t.(IStandaloneFunctionContext)
			i++
		}
	}

	return tst
}

func (s *ExpressionContext) StandaloneFunction(i int) IStandaloneFunctionContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IStandaloneFunctionContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IStandaloneFunctionContext)
}

func (s *ExpressionContext) AllLiteral() []ILiteralContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(ILiteralContext); ok {
			len++
		}
	}

	tst := make([]ILiteralContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(ILiteralContext); ok {
			tst[i] = t.(ILiteralContext)
			i++
		}
	}

	return tst
}

func (s *ExpressionContext) Literal(i int) ILiteralContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(ILiteralContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(ILiteralContext)
}

func (s *ExpressionContext) AllExpression() []IExpressionContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IExpressionContext); ok {
			len++
		}
	}

	tst := make([]IExpressionContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IExpressionContext); ok {
			tst[i] = t.(IExpressionContext)
			i++
		}
	}

	return tst
}

func (s *ExpressionContext) Expression(i int) IExpressionContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpressionContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpressionContext)
}

func (s *ExpressionContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpressionContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ExpressionContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterExpression(s)
	}
}

func (s *ExpressionContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitExpression(s)
	}
}

func (p *dae_configParser) Expression() (localctx IExpressionContext) {
	localctx = NewExpressionContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 4, dae_configParserRULE_expression)
	var _la int

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(32)
		p.Match(dae_configParserID)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}
	{
		p.SetState(33)
		p.Match(dae_configParserT__0)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}
	p.SetState(41)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_la = p.GetTokenStream().LA(1)

	for (int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&229632) != 0 {
		p.SetState(39)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}

		switch p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 1, p.GetParserRuleContext()) {
		case 1:
			{
				p.SetState(34)
				p.ArrowExpression()
			}

		case 2:
			{
				p.SetState(35)
				p.Declaration()
			}

		case 3:
			{
				p.SetState(36)
				p.StandaloneFunction()
			}

		case 4:
			{
				p.SetState(37)
				p.Literal()
			}

		case 5:
			{
				p.SetState(38)
				p.Expression()
			}

		case antlr.ATNInvalidAltNumber:
			goto errorExit
		}

		p.SetState(43)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)
	}
	{
		p.SetState(44)
		p.Match(dae_configParserT__1)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// IDeclarationContext is an interface to support dynamic dispatch.
type IDeclarationContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetKey returns the key token.
	GetKey() antlr.Token

	// SetKey sets the key token.
	SetKey(antlr.Token)

	// Getter signatures
	AllFunctionPrototype() []IFunctionPrototypeContext
	FunctionPrototype(i int) IFunctionPrototypeContext
	OptAnnotation() IOptAnnotationContext
	ID() antlr.TerminalNode
	NON_ID() antlr.TerminalNode
	QUOTE_STRING() antlr.TerminalNode
	AllLiteral() []ILiteralContext
	Literal(i int) ILiteralContext

	// IsDeclarationContext differentiates from other interfaces.
	IsDeclarationContext()
}

type DeclarationContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
	key    antlr.Token
}

func NewEmptyDeclarationContext() *DeclarationContext {
	var p = new(DeclarationContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_declaration
	return p
}

func InitEmptyDeclarationContext(p *DeclarationContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_declaration
}

func (*DeclarationContext) IsDeclarationContext() {}

func NewDeclarationContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *DeclarationContext {
	var p = new(DeclarationContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_declaration

	return p
}

func (s *DeclarationContext) GetParser() antlr.Parser { return s.parser }

func (s *DeclarationContext) GetKey() antlr.Token { return s.key }

func (s *DeclarationContext) SetKey(v antlr.Token) { s.key = v }

func (s *DeclarationContext) AllFunctionPrototype() []IFunctionPrototypeContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IFunctionPrototypeContext); ok {
			len++
		}
	}

	tst := make([]IFunctionPrototypeContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IFunctionPrototypeContext); ok {
			tst[i] = t.(IFunctionPrototypeContext)
			i++
		}
	}

	return tst
}

func (s *DeclarationContext) FunctionPrototype(i int) IFunctionPrototypeContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IFunctionPrototypeContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IFunctionPrototypeContext)
}

func (s *DeclarationContext) OptAnnotation() IOptAnnotationContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IOptAnnotationContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IOptAnnotationContext)
}

func (s *DeclarationContext) ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserID, 0)
}

func (s *DeclarationContext) NON_ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserNON_ID, 0)
}

func (s *DeclarationContext) QUOTE_STRING() antlr.TerminalNode {
	return s.GetToken(dae_configParserQUOTE_STRING, 0)
}

func (s *DeclarationContext) AllLiteral() []ILiteralContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(ILiteralContext); ok {
			len++
		}
	}

	tst := make([]ILiteralContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(ILiteralContext); ok {
			tst[i] = t.(ILiteralContext)
			i++
		}
	}

	return tst
}

func (s *DeclarationContext) Literal(i int) ILiteralContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(ILiteralContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(ILiteralContext)
}

func (s *DeclarationContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *DeclarationContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *DeclarationContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterDeclaration(s)
	}
}

func (s *DeclarationContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitDeclaration(s)
	}
}

func (p *dae_configParser) Declaration() (localctx IDeclarationContext) {
	localctx = NewDeclarationContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 6, dae_configParserRULE_declaration)
	var _la int

	p.SetState(70)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}

	switch p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 5, p.GetParserRuleContext()) {
	case 1:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(46)

			var _lt = p.GetTokenStream().LT(1)

			localctx.(*DeclarationContext).key = _lt

			_la = p.GetTokenStream().LA(1)

			if !((int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&229376) != 0) {
				var _ri = p.GetErrorHandler().RecoverInline(p)

				localctx.(*DeclarationContext).key = _ri
			} else {
				p.GetErrorHandler().ReportMatch(p)
				p.Consume()
			}
		}
		{
			p.SetState(47)
			p.Match(dae_configParserT__2)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}
		{
			p.SetState(48)
			p.FunctionPrototype()
		}
		p.SetState(53)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)

		for _la == dae_configParserT__3 {
			{
				p.SetState(49)
				p.Match(dae_configParserT__3)
				if p.HasError() {
					// Recognition error - abort rule
					goto errorExit
				}
			}
			{
				p.SetState(50)
				p.FunctionPrototype()
			}

			p.SetState(55)
			p.GetErrorHandler().Sync(p)
			if p.HasError() {
				goto errorExit
			}
			_la = p.GetTokenStream().LA(1)
		}
		{
			p.SetState(56)
			p.OptAnnotation()
		}

	case 2:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(58)

			var _lt = p.GetTokenStream().LT(1)

			localctx.(*DeclarationContext).key = _lt

			_la = p.GetTokenStream().LA(1)

			if !((int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&229376) != 0) {
				var _ri = p.GetErrorHandler().RecoverInline(p)

				localctx.(*DeclarationContext).key = _ri
			} else {
				p.GetErrorHandler().ReportMatch(p)
				p.Consume()
			}
		}
		{
			p.SetState(59)
			p.Match(dae_configParserT__2)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}
		{
			p.SetState(60)
			p.Literal()
		}
		p.SetState(65)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)

		for _la == dae_configParserT__4 {
			{
				p.SetState(61)
				p.Match(dae_configParserT__4)
				if p.HasError() {
					// Recognition error - abort rule
					goto errorExit
				}
			}
			{
				p.SetState(62)
				p.Literal()
			}

			p.SetState(67)
			p.GetErrorHandler().Sync(p)
			if p.HasError() {
				goto errorExit
			}
			_la = p.GetTokenStream().LA(1)
		}
		{
			p.SetState(68)
			p.OptAnnotation()
		}

	case antlr.ATNInvalidAltNumber:
		goto errorExit
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// IOptAnnotationContext is an interface to support dynamic dispatch.
type IOptAnnotationContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	AllAnnotationParameter() []IAnnotationParameterContext
	AnnotationParameter(i int) IAnnotationParameterContext

	// IsOptAnnotationContext differentiates from other interfaces.
	IsOptAnnotationContext()
}

type OptAnnotationContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyOptAnnotationContext() *OptAnnotationContext {
	var p = new(OptAnnotationContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_optAnnotation
	return p
}

func InitEmptyOptAnnotationContext(p *OptAnnotationContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_optAnnotation
}

func (*OptAnnotationContext) IsOptAnnotationContext() {}

func NewOptAnnotationContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *OptAnnotationContext {
	var p = new(OptAnnotationContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_optAnnotation

	return p
}

func (s *OptAnnotationContext) GetParser() antlr.Parser { return s.parser }

func (s *OptAnnotationContext) AllAnnotationParameter() []IAnnotationParameterContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IAnnotationParameterContext); ok {
			len++
		}
	}

	tst := make([]IAnnotationParameterContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IAnnotationParameterContext); ok {
			tst[i] = t.(IAnnotationParameterContext)
			i++
		}
	}

	return tst
}

func (s *OptAnnotationContext) AnnotationParameter(i int) IAnnotationParameterContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IAnnotationParameterContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IAnnotationParameterContext)
}

func (s *OptAnnotationContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *OptAnnotationContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *OptAnnotationContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterOptAnnotation(s)
	}
}

func (s *OptAnnotationContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitOptAnnotation(s)
	}
}

func (p *dae_configParser) OptAnnotation() (localctx IOptAnnotationContext) {
	localctx = NewOptAnnotationContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 8, dae_configParserRULE_optAnnotation)
	var _la int

	p.SetState(85)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}

	switch p.GetTokenStream().LA(1) {
	case dae_configParserT__5:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(72)
			p.Match(dae_configParserT__5)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}
		p.SetState(81)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)

		if (int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&229376) != 0 {
			{
				p.SetState(73)
				p.AnnotationParameter()
			}
			p.SetState(78)
			p.GetErrorHandler().Sync(p)
			if p.HasError() {
				goto errorExit
			}
			_la = p.GetTokenStream().LA(1)

			for _la == dae_configParserT__4 {
				{
					p.SetState(74)
					p.Match(dae_configParserT__4)
					if p.HasError() {
						// Recognition error - abort rule
						goto errorExit
					}
				}
				{
					p.SetState(75)
					p.AnnotationParameter()
				}

				p.SetState(80)
				p.GetErrorHandler().Sync(p)
				if p.HasError() {
					goto errorExit
				}
				_la = p.GetTokenStream().LA(1)
			}

		}
		{
			p.SetState(83)
			p.Match(dae_configParserT__6)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}

	case dae_configParserT__1, dae_configParserT__7, dae_configParserT__10, dae_configParserID, dae_configParserNON_ID, dae_configParserQUOTE_STRING:
		p.EnterOuterAlt(localctx, 2)

	default:
		p.SetError(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
		goto errorExit
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// IAnnotationParameterContext is an interface to support dynamic dispatch.
type IAnnotationParameterContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	Parameter() IParameterContext
	ID() antlr.TerminalNode
	FunctionPrototype() IFunctionPrototypeContext

	// IsAnnotationParameterContext differentiates from other interfaces.
	IsAnnotationParameterContext()
}

type AnnotationParameterContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyAnnotationParameterContext() *AnnotationParameterContext {
	var p = new(AnnotationParameterContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_annotationParameter
	return p
}

func InitEmptyAnnotationParameterContext(p *AnnotationParameterContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_annotationParameter
}

func (*AnnotationParameterContext) IsAnnotationParameterContext() {}

func NewAnnotationParameterContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *AnnotationParameterContext {
	var p = new(AnnotationParameterContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_annotationParameter

	return p
}

func (s *AnnotationParameterContext) GetParser() antlr.Parser { return s.parser }

func (s *AnnotationParameterContext) Parameter() IParameterContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IParameterContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IParameterContext)
}

func (s *AnnotationParameterContext) ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserID, 0)
}

func (s *AnnotationParameterContext) FunctionPrototype() IFunctionPrototypeContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IFunctionPrototypeContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IFunctionPrototypeContext)
}

func (s *AnnotationParameterContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *AnnotationParameterContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *AnnotationParameterContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterAnnotationParameter(s)
	}
}

func (s *AnnotationParameterContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitAnnotationParameter(s)
	}
}

func (p *dae_configParser) AnnotationParameter() (localctx IAnnotationParameterContext) {
	localctx = NewAnnotationParameterContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 10, dae_configParserRULE_annotationParameter)
	p.SetState(91)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}

	switch p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 9, p.GetParserRuleContext()) {
	case 1:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(87)
			p.Parameter()
		}

	case 2:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(88)
			p.Match(dae_configParserID)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}
		{
			p.SetState(89)
			p.Match(dae_configParserT__2)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}
		{
			p.SetState(90)
			p.FunctionPrototype()
		}

	case antlr.ATNInvalidAltNumber:
		goto errorExit
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// IFunctionPrototypeContext is an interface to support dynamic dispatch.
type IFunctionPrototypeContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	ID() antlr.TerminalNode
	NON_ID() antlr.TerminalNode
	QUOTE_STRING() antlr.TerminalNode
	AllParameter() []IParameterContext
	Parameter(i int) IParameterContext

	// IsFunctionPrototypeContext differentiates from other interfaces.
	IsFunctionPrototypeContext()
}

type FunctionPrototypeContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyFunctionPrototypeContext() *FunctionPrototypeContext {
	var p = new(FunctionPrototypeContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_functionPrototype
	return p
}

func InitEmptyFunctionPrototypeContext(p *FunctionPrototypeContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_functionPrototype
}

func (*FunctionPrototypeContext) IsFunctionPrototypeContext() {}

func NewFunctionPrototypeContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *FunctionPrototypeContext {
	var p = new(FunctionPrototypeContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_functionPrototype

	return p
}

func (s *FunctionPrototypeContext) GetParser() antlr.Parser { return s.parser }

func (s *FunctionPrototypeContext) ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserID, 0)
}

func (s *FunctionPrototypeContext) NON_ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserNON_ID, 0)
}

func (s *FunctionPrototypeContext) QUOTE_STRING() antlr.TerminalNode {
	return s.GetToken(dae_configParserQUOTE_STRING, 0)
}

func (s *FunctionPrototypeContext) AllParameter() []IParameterContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IParameterContext); ok {
			len++
		}
	}

	tst := make([]IParameterContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IParameterContext); ok {
			tst[i] = t.(IParameterContext)
			i++
		}
	}

	return tst
}

func (s *FunctionPrototypeContext) Parameter(i int) IParameterContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IParameterContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IParameterContext)
}

func (s *FunctionPrototypeContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *FunctionPrototypeContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *FunctionPrototypeContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterFunctionPrototype(s)
	}
}

func (s *FunctionPrototypeContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitFunctionPrototype(s)
	}
}

func (p *dae_configParser) FunctionPrototype() (localctx IFunctionPrototypeContext) {
	localctx = NewFunctionPrototypeContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 12, dae_configParserRULE_functionPrototype)
	var _la int

	p.EnterOuterAlt(localctx, 1)
	p.SetState(94)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_la = p.GetTokenStream().LA(1)

	if _la == dae_configParserT__7 {
		{
			p.SetState(93)
			p.Match(dae_configParserT__7)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}

	}
	{
		p.SetState(96)
		_la = p.GetTokenStream().LA(1)

		if !((int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&229376) != 0) {
			p.GetErrorHandler().RecoverInline(p)
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}
	{
		p.SetState(97)
		p.Match(dae_configParserT__8)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}
	p.SetState(106)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_la = p.GetTokenStream().LA(1)

	if (int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&229376) != 0 {
		{
			p.SetState(98)
			p.Parameter()
		}
		p.SetState(103)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)

		for _la == dae_configParserT__4 {
			{
				p.SetState(99)
				p.Match(dae_configParserT__4)
				if p.HasError() {
					// Recognition error - abort rule
					goto errorExit
				}
			}
			{
				p.SetState(100)
				p.Parameter()
			}

			p.SetState(105)
			p.GetErrorHandler().Sync(p)
			if p.HasError() {
				goto errorExit
			}
			_la = p.GetTokenStream().LA(1)
		}

	}
	{
		p.SetState(108)
		p.Match(dae_configParserT__9)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// IParameterContext is an interface to support dynamic dispatch.
type IParameterContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	ID() antlr.TerminalNode
	Literal() ILiteralContext

	// IsParameterContext differentiates from other interfaces.
	IsParameterContext()
}

type ParameterContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyParameterContext() *ParameterContext {
	var p = new(ParameterContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_parameter
	return p
}

func InitEmptyParameterContext(p *ParameterContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_parameter
}

func (*ParameterContext) IsParameterContext() {}

func NewParameterContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ParameterContext {
	var p = new(ParameterContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_parameter

	return p
}

func (s *ParameterContext) GetParser() antlr.Parser { return s.parser }

func (s *ParameterContext) ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserID, 0)
}

func (s *ParameterContext) Literal() ILiteralContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(ILiteralContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(ILiteralContext)
}

func (s *ParameterContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ParameterContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ParameterContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterParameter(s)
	}
}

func (s *ParameterContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitParameter(s)
	}
}

func (p *dae_configParser) Parameter() (localctx IParameterContext) {
	localctx = NewParameterContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 14, dae_configParserRULE_parameter)
	p.SetState(114)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}

	switch p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 13, p.GetParserRuleContext()) {
	case 1:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(110)
			p.Match(dae_configParserID)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}
		{
			p.SetState(111)
			p.Match(dae_configParserT__2)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}
		{
			p.SetState(112)
			p.Literal()
		}

	case 2:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(113)
			p.Literal()
		}

	case antlr.ATNInvalidAltNumber:
		goto errorExit
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// IArrowExpressionContext is an interface to support dynamic dispatch.
type IArrowExpressionContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	AllArrowOperand() []IArrowOperandContext
	ArrowOperand(i int) IArrowOperandContext

	// IsArrowExpressionContext differentiates from other interfaces.
	IsArrowExpressionContext()
}

type ArrowExpressionContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyArrowExpressionContext() *ArrowExpressionContext {
	var p = new(ArrowExpressionContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_arrowExpression
	return p
}

func InitEmptyArrowExpressionContext(p *ArrowExpressionContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_arrowExpression
}

func (*ArrowExpressionContext) IsArrowExpressionContext() {}

func NewArrowExpressionContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ArrowExpressionContext {
	var p = new(ArrowExpressionContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_arrowExpression

	return p
}

func (s *ArrowExpressionContext) GetParser() antlr.Parser { return s.parser }

func (s *ArrowExpressionContext) AllArrowOperand() []IArrowOperandContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IArrowOperandContext); ok {
			len++
		}
	}

	tst := make([]IArrowOperandContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IArrowOperandContext); ok {
			tst[i] = t.(IArrowOperandContext)
			i++
		}
	}

	return tst
}

func (s *ArrowExpressionContext) ArrowOperand(i int) IArrowOperandContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IArrowOperandContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IArrowOperandContext)
}

func (s *ArrowExpressionContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ArrowExpressionContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ArrowExpressionContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterArrowExpression(s)
	}
}

func (s *ArrowExpressionContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitArrowExpression(s)
	}
}

func (p *dae_configParser) ArrowExpression() (localctx IArrowExpressionContext) {
	localctx = NewArrowExpressionContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 16, dae_configParserRULE_arrowExpression)
	var _la int

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(116)
		p.ArrowOperand()
	}
	{
		p.SetState(117)
		p.Match(dae_configParserT__10)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}
	{
		p.SetState(118)
		p.ArrowOperand()
	}
	p.SetState(123)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_la = p.GetTokenStream().LA(1)

	for _la == dae_configParserT__10 {
		{
			p.SetState(119)
			p.Match(dae_configParserT__10)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}
		{
			p.SetState(120)
			p.ArrowOperand()
		}

		p.SetState(125)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// IArrowOperandContext is an interface to support dynamic dispatch.
type IArrowOperandContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	ID() antlr.TerminalNode
	AllFunctionPrototype() []IFunctionPrototypeContext
	FunctionPrototype(i int) IFunctionPrototypeContext
	OptAnnotation() IOptAnnotationContext
	Literal() ILiteralContext

	// IsArrowOperandContext differentiates from other interfaces.
	IsArrowOperandContext()
}

type ArrowOperandContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyArrowOperandContext() *ArrowOperandContext {
	var p = new(ArrowOperandContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_arrowOperand
	return p
}

func InitEmptyArrowOperandContext(p *ArrowOperandContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_arrowOperand
}

func (*ArrowOperandContext) IsArrowOperandContext() {}

func NewArrowOperandContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ArrowOperandContext {
	var p = new(ArrowOperandContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_arrowOperand

	return p
}

func (s *ArrowOperandContext) GetParser() antlr.Parser { return s.parser }

func (s *ArrowOperandContext) ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserID, 0)
}

func (s *ArrowOperandContext) AllFunctionPrototype() []IFunctionPrototypeContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IFunctionPrototypeContext); ok {
			len++
		}
	}

	tst := make([]IFunctionPrototypeContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IFunctionPrototypeContext); ok {
			tst[i] = t.(IFunctionPrototypeContext)
			i++
		}
	}

	return tst
}

func (s *ArrowOperandContext) FunctionPrototype(i int) IFunctionPrototypeContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IFunctionPrototypeContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IFunctionPrototypeContext)
}

func (s *ArrowOperandContext) OptAnnotation() IOptAnnotationContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IOptAnnotationContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IOptAnnotationContext)
}

func (s *ArrowOperandContext) Literal() ILiteralContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(ILiteralContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(ILiteralContext)
}

func (s *ArrowOperandContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ArrowOperandContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ArrowOperandContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterArrowOperand(s)
	}
}

func (s *ArrowOperandContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitArrowOperand(s)
	}
}

func (p *dae_configParser) ArrowOperand() (localctx IArrowOperandContext) {
	localctx = NewArrowOperandContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 18, dae_configParserRULE_arrowOperand)
	var _la int

	p.SetState(149)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}

	switch p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 17, p.GetParserRuleContext()) {
	case 1:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(126)
			p.Match(dae_configParserID)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}
		{
			p.SetState(127)
			p.Match(dae_configParserT__2)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}
		{
			p.SetState(128)
			p.FunctionPrototype()
		}
		p.SetState(133)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)

		for _la == dae_configParserT__3 {
			{
				p.SetState(129)
				p.Match(dae_configParserT__3)
				if p.HasError() {
					// Recognition error - abort rule
					goto errorExit
				}
			}
			{
				p.SetState(130)
				p.FunctionPrototype()
			}

			p.SetState(135)
			p.GetErrorHandler().Sync(p)
			if p.HasError() {
				goto errorExit
			}
			_la = p.GetTokenStream().LA(1)
		}
		{
			p.SetState(136)
			p.OptAnnotation()
		}

	case 2:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(138)
			p.FunctionPrototype()
		}
		p.SetState(143)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)

		for _la == dae_configParserT__3 {
			{
				p.SetState(139)
				p.Match(dae_configParserT__3)
				if p.HasError() {
					// Recognition error - abort rule
					goto errorExit
				}
			}
			{
				p.SetState(140)
				p.FunctionPrototype()
			}

			p.SetState(145)
			p.GetErrorHandler().Sync(p)
			if p.HasError() {
				goto errorExit
			}
			_la = p.GetTokenStream().LA(1)
		}
		{
			p.SetState(146)
			p.OptAnnotation()
		}

	case 3:
		p.EnterOuterAlt(localctx, 3)
		{
			p.SetState(148)
			p.Literal()
		}

	case antlr.ATNInvalidAltNumber:
		goto errorExit
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// IStandaloneFunctionContext is an interface to support dynamic dispatch.
type IStandaloneFunctionContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	FunctionPrototype() IFunctionPrototypeContext
	OptAnnotation() IOptAnnotationContext

	// IsStandaloneFunctionContext differentiates from other interfaces.
	IsStandaloneFunctionContext()
}

type StandaloneFunctionContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyStandaloneFunctionContext() *StandaloneFunctionContext {
	var p = new(StandaloneFunctionContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_standaloneFunction
	return p
}

func InitEmptyStandaloneFunctionContext(p *StandaloneFunctionContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = dae_configParserRULE_standaloneFunction
}

func (*StandaloneFunctionContext) IsStandaloneFunctionContext() {}

func NewStandaloneFunctionContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *StandaloneFunctionContext {
	var p = new(StandaloneFunctionContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_standaloneFunction

	return p
}

func (s *StandaloneFunctionContext) GetParser() antlr.Parser { return s.parser }

func (s *StandaloneFunctionContext) FunctionPrototype() IFunctionPrototypeContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IFunctionPrototypeContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IFunctionPrototypeContext)
}

func (s *StandaloneFunctionContext) OptAnnotation() IOptAnnotationContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IOptAnnotationContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IOptAnnotationContext)
}

func (s *StandaloneFunctionContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *StandaloneFunctionContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *StandaloneFunctionContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterStandaloneFunction(s)
	}
}

func (s *StandaloneFunctionContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitStandaloneFunction(s)
	}
}

func (p *dae_configParser) StandaloneFunction() (localctx IStandaloneFunctionContext) {
	localctx = NewStandaloneFunctionContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 20, dae_configParserRULE_standaloneFunction)
	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(151)
		p.FunctionPrototype()
	}
	{
		p.SetState(152)
		p.OptAnnotation()
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}
