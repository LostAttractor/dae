/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"github.com/antlr/antlr4/runtime/Go/antlr/v4"
	"github.com/daeuniverse/dae-config-dist/go/dae_config"
)

func Parse(in string) (sections []*Section, err error) {
	errorListener := &syntaxErrorListener{DefaultErrorListener: antlr.NewDefaultErrorListener()}
	lexer := dae_config.Newdae_configLexer(antlr.NewInputStream(in))
	lexer.RemoveErrorListeners()
	lexer.AddErrorListener(errorListener)
	input := antlr.NewCommonTokenStream(lexer, 0)

	parser := dae_config.Newdae_configParser(input)
	parser.RemoveErrorListeners()
	parser.AddErrorListener(errorListener)
	parser.BuildParseTrees = true
	tree := parser.Start()
	if errorListener.err != nil {
		return nil, errorListener.err
	}

	decoder := new(decoder)
	sections = decoder.decode(tree)
	if decoder.err != nil {
		return nil, decoder.err
	}
	return sections, nil
}
