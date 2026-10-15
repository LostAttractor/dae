package dae_config

import (
	"fmt"
	"testing"

	"github.com/antlr4-go/antlr/v4"
)

type syntaxErrorListener struct {
	*antlr.DefaultErrorListener
	errors []string
}

func (l *syntaxErrorListener) SyntaxError(_ antlr.Recognizer, _ any, line, column int, msg string, _ antlr.RecognitionException) {
	l.errors = append(l.errors, fmt.Sprintf("%d:%d: %s", line, column, msg))
}

func newParser(source string) (*dae_configParser, *syntaxErrorListener) {
	errors := &syntaxErrorListener{DefaultErrorListener: antlr.NewDefaultErrorListener()}
	lexer := Newdae_configLexer(antlr.NewInputStream(source))
	lexer.RemoveErrorListeners()
	lexer.AddErrorListener(errors)
	parser := Newdae_configParser(antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel))
	parser.RemoveErrorListeners()
	parser.AddErrorListener(errors)
	return parser, errors
}

func requireCompleteParse(t *testing.T, parser *dae_configParser, errors *syntaxErrorListener) {
	t.Helper()
	if len(errors.errors) != 0 {
		t.Fatalf("syntax errors: %v", errors.errors)
	}
	if token := parser.GetCurrentToken(); token.GetTokenType() != antlr.TokenEOF {
		t.Fatalf("unparsed input starts at %q", token.GetText())
	}
}

func TestOutboundExprLiteralsAndParams(t *testing.T) {
	for _, outbound := range []string{
		"proxy",
		"'香港 01'",
		"proxy(skip_while_noalive)",
		"123(mark: 1)",
		"'香港 01'(mark: 0x800, skip_while_noalive)",
	} {
		parser, errors := newParser("routing { domain(full: example.com) -> " + outbound + " }")
		parser.Start_()
		requireCompleteParse(t, parser, errors)
	}
}

func TestQuotedLiteralEscapes(t *testing.T) {
	for _, literal := range []string{
		`"Node \"A\" \\ path"`,
		`'Node \'A\' \\ path'`,
		`"trailing\\"`,
		`'trailing\\'`,
		`'^HK\d+$'`,
	} {
		parser, errors := newParser("routing { domain(full: example.com) -> " + literal + " }")
		parser.Start_()
		requireCompleteParse(t, parser, errors)
	}
}

func TestQuotedLiteralControlCharacters(t *testing.T) {
	for _, literal := range []string{
		"\"line one\n\tline two\"",
		"'line one\n\tline two'",
	} {
		parser, errors := newParser("routing { domain(full: example.com) -> " + literal + " }")
		parser.Start_()
		requireCompleteParse(t, parser, errors)
	}
}

func TestFallbackDeclarationSupportsOutboundParams(t *testing.T) {
	for _, outbound := range []string{
		"proxy(skip_while_noalive)",
		"'香港 01'(mark: 0x800, skip_while_noalive)",
	} {
		t.Run(outbound, func(t *testing.T) {
			parser, errors := newParser("routing { fallback: " + outbound + " }")
			parser.Start_()
			requireCompleteParse(t, parser, errors)
		})
	}
}

func TestLegacyCallableAnnotationRemainsParseableForMigrationError(t *testing.T) {
	parser, errors := newParser("group { target { filter: name(exit) [via: node(entry)] } }")
	parser.Start_()
	requireCompleteParse(t, parser, errors)
}

func TestProxyPathExpressions(t *testing.T) {
	for _, source := range []string{
		"group { target { filter: node(lightsail) -> filter: subtag(flowercloud) && name(keyword: '日本') policy: min_moving_avg } }",
		"group { target { node(entry) -> group(middle) -> filter: subtag(exit) [priority: 1] } }",
		"group { target { node(entry) -> group(middle) -> node(exit) } }",
		"group { target { group('entry path') } }",
		"group { target { node(entry) -> group(exit) } }",
	} {
		parser, errors := newParser(source)
		parser.Start_()
		requireCompleteParse(t, parser, errors)
	}
}

func TestProxyPathRejectsDanglingArrow(t *testing.T) {
	parser, errors := newParser("group { target { filter: node(entry) -> } }")
	parser.Start_()
	if len(errors.errors) == 0 {
		t.Fatal("dangling proxy path arrow was accepted")
	}
}

func TestOrdinaryParameterRejectsFunctionValue(t *testing.T) {
	parser, errors := newParser("routing { domain(value: nested(foo)) -> direct }")
	parser.Start_()
	if len(errors.errors) == 0 {
		t.Fatal("function-valued ordinary parameter was accepted")
	}
}

func TestDeclarationKeys(t *testing.T) {
	for _, key := range []string{"br-lan", "123", `"foo,bar"`, `'wan\backup'`, `"网卡"`} {
		parser, errors := newParser("routing { interface { " + key + ": main } }")
		parser.Start_()
		requireCompleteParse(t, parser, errors)
	}
}
