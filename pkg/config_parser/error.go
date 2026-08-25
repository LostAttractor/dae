/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"fmt"
	"strings"

	"github.com/antlr/antlr4/runtime/Go/antlr/v4"
)

type ConsoleErrorListener struct {
	ErrorBuilder strings.Builder
}

func NewConsoleErrorListener() *ConsoleErrorListener {
	return &ConsoleErrorListener{}
}

func (d *ConsoleErrorListener) SyntaxError(recognizer antlr.Recognizer, offendingSymbol interface{}, line, column int, msg string, e antlr.RecognitionException) {
	// Do not accumulate errors.
	if d.ErrorBuilder.Len() > 0 {
		return
	}
	backtrack := min(column, 30)
	starting := fmt.Sprintf("line %v:%v ", line, column)
	offset := len(starting) + backtrack
	token, ok := offendingSymbol.(antlr.Token)
	if !ok || token.GetTokenType() == -1 {
		d.ErrorBuilder.WriteString(starting + msg)
		return
	}

	beginOfLine := token.GetStart() - backtrack
	strPeek := token.GetInputStream().GetText(beginOfLine, token.GetStop()+30)
	wrap := strings.IndexByte(strPeek, '\n')
	if wrap == -1 {
		wrap = token.GetStop() + 30
	} else {
		wrap += beginOfLine - 1
	}
	strLine := token.GetInputStream().GetText(beginOfLine, wrap)
	d.ErrorBuilder.WriteString(fmt.Sprintf("%v%v\n%v%v: %v\n", starting, strLine, strings.Repeat(" ", offset), strings.Repeat("^", token.GetStop()-token.GetStart()+1), msg))
}
func (d *ConsoleErrorListener) ReportAmbiguity(recognizer antlr.Parser, dfa *antlr.DFA, startIndex, stopIndex int, exact bool, ambigAlts *antlr.BitSet, configs antlr.ATNConfigSet) {
}

func (d *ConsoleErrorListener) ReportAttemptingFullContext(recognizer antlr.Parser, dfa *antlr.DFA, startIndex, stopIndex int, conflictingAlts *antlr.BitSet, configs antlr.ATNConfigSet) {
}

func (d *ConsoleErrorListener) ReportContextSensitivity(recognizer antlr.Parser, dfa *antlr.DFA, startIndex, stopIndex, prediction int, configs antlr.ATNConfigSet) {
}
