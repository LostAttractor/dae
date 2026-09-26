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

func (l *syntaxErrorListener) SyntaxError(recognizer antlr.Recognizer, offendingSymbol any, line, column int, _ string, _ antlr.RecognitionException) {
	if l.err != nil {
		return
	}
	message := "invalid token"
	if parser, ok := recognizer.(antlr.Parser); ok {
		message = "invalid syntax; expected " + parser.GetExpectedTokens().StringVerbose(parser.GetLiteralNames(), parser.GetSymbolicNames(), false)
		if token, ok := offendingSymbol.(antlr.Token); ok && token.GetText() == ":" {
			// Use fixed examples rather than echoing potentially secret configuration values.
			message += "; unexpected ':' (key/value separator); if ':' is part of a value, quote the entire value, e.g. '192.0.2.1:443' or '[2001:db8::1]:443'"
		}
	}
	l.err = fmt.Errorf("line %d:%d %s", line, column, message)
}
