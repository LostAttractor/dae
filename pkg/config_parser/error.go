/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"fmt"

	"github.com/antlr4-go/antlr/v4"
)

type syntaxErrorListener struct {
	*antlr.DefaultErrorListener
	err error
}

func (l *syntaxErrorListener) SyntaxError(recognizer antlr.Recognizer, _ any, line, column int, _ string, _ antlr.RecognitionException) {
	if l.err != nil {
		return
	}
	message := "invalid token"
	if parser, ok := recognizer.(antlr.Parser); ok {
		message = "invalid syntax; expected " + parser.GetExpectedTokens().StringVerbose(parser.GetLiteralNames(), parser.GetSymbolicNames(), false)
	}
	l.err = fmt.Errorf("line %d:%d %s", line, column, message)
}
