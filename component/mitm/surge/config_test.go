package surge

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestSurgeModuleSourcesRejectInvalidDeclarations(t *testing.T) {
	for _, test := range []struct {
		name, body, errorText string
	}{
		{
			name:      "scalar source",
			body:      `module: 'https://example.com/module.sgmodule'`,
			errorText: "requires a section",
		},
		{
			name:      "named empty source",
			body:      `module { empty: '' }`,
			errorText: "non-empty source",
		},
		{
			name:      "anonymous empty source",
			body:      `module { '' }`,
			errorText: "non-empty source",
		},
		{
			name:      "whitespace source",
			body:      `module { empty: '   ' }`,
			errorText: "non-empty source",
		},
		{
			name:      "source annotation",
			body:      `module { test: 'https://example.com/module.sgmodule' [enabled: true] }`,
			errorText: "without annotations",
		},
		{
			name:      "function source",
			body:      `module { test: name(example) }`,
			errorText: "must be a literal source",
		},
		{
			name:      "expanded source missing link",
			body:      `module { test { arguments { 'key=value' } } }`,
			errorText: "missing link",
		},
		{
			name:      "expanded empty source",
			body:      `module { test { link: '  ' } }`,
			errorText: "non-empty source",
		},
		{
			name:      "expanded duplicate link",
			body:      `module { test { link: 'file:first' link: 'file:second' } }`,
			errorText: "duplicate link",
		},
		{
			name:      "expanded unknown field",
			body:      `module { test { link: 'file:test' unknown: true } }`,
			errorText: "expected a literal link",
		},
		{
			name:      "expanded unknown section",
			body:      `module { test { link: 'file:test' option {} } }`,
			errorText: `unknown section "option"`,
		},
		{
			name:      "expanded annotated link",
			body:      `module { test { link: 'file:test' [enabled: true] } }`,
			errorText: "expected a literal link without annotations",
		},
		{
			name:      "expanded function link",
			body:      `module { test { link: name(test) } }`,
			errorText: "expected a literal link",
		},
		{
			name:      "duplicate arguments section",
			body:      `module { test { link: 'file:test' arguments {} arguments {} } }`,
			errorText: "duplicate arguments section",
		},
		{
			name:      "scalar arguments",
			body:      `module { test { link: 'file:test' arguments: 'key=value' } }`,
			errorText: "expected a literal link",
		},
		{
			name:      "duplicate argument",
			body:      `module { test { link: 'file:test' arguments { '屏蔽上传按钮=true' ' 屏蔽上传按钮 =false' } } }`,
			errorText: `duplicate argument "屏蔽上传按钮"`,
		},
		{
			name:      "argument without equals",
			body:      `module { test { link: 'file:test' arguments { '字幕翻译语言' } } }`,
			errorText: "non-empty name",
		},
		{
			name:      "argument without name",
			body:      `module { test { link: 'file:test' arguments { ' =value' } } }`,
			errorText: "non-empty name",
		},
		{
			name:      "named argument",
			body:      `module { test { link: 'file:test' arguments { enabled: 'false' } } }`,
			errorText: "literal 'name=value' entries",
		},
		{
			name:      "argument function",
			body:      `module { test { link: 'file:test' arguments { enabled: name(false) } } }`,
			errorText: "literal 'name=value' entries",
		},
		{
			name:      "argument annotation",
			body:      `module { test { link: 'file:test' arguments { enabled: 'false' [other: true] } } }`,
			errorText: "without annotations",
		},
		{
			name:      "argument section",
			body:      `module { test { link: 'file:test' arguments { enabled {} } } }`,
			errorText: "literal 'name=value' entries",
		},
		{
			name:      "duplicate expanded name",
			body:      `module { test: 'file:first' test { link: 'file:second' arguments { 'key=value' } } }`,
			errorText: `duplicate module name "test"`,
		},
		{
			name: "duplicate name",
			body: `module {
  test: 'https://example.com/first.sgmodule'
  test: 'https://example.com/second.sgmodule'
}`,
			errorText: `duplicate module name "test"`,
		},
		{
			name: "duplicate name across sections",
			body: `module { test: 'https://example.com/first.sgmodule' }
module { test: 'https://example.com/second.sgmodule' }`,
			errorText: `duplicate module name "test"`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sections, err := config_parser.Parse("surge {\n" + test.body + "\n}")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseConfig(sections[0]); err == nil || !strings.Contains(err.Error(), test.errorText) {
				t.Fatalf("parse error = %v, want %q", err, test.errorText)
			}
		})
	}
}

func TestSurgeModuleSourcesAndArgumentsRoundTrip(t *testing.T) {
	conf := parseConfig(t, `global {}
plugins {
 surge {
  module {
    youtube {
      arguments {
        '屏蔽上传按钮=false'
        '字幕翻译语言=zh-CN'
        ' empty ='
        'zero=0'
        'text=  keep spaces = [x],{} # literal  '
        'quoted key "双引号"=both \'apostrophe\' and "quotes" \\ path'
        'line=one
two'
      }
      link: 'https://example.com/youtube.sgmodule?token=a=b,c'
    }
    expanded { link: 'file:expanded' }
    empty_arguments { link: 'file:empty' arguments {} }
    simple: 'file:simple'
    'file:///var/lib/dae/anonymous'
  }
  module { 'http://example.com/another.sgmodule' }
 }
}
routing { fallback: direct }
`)
	want := []ModuleSource{
		{
			Name: "youtube",
			Link: "https://example.com/youtube.sgmodule?token=a=b,c",
			Arguments: map[string]string{
				"屏蔽上传按钮":           "false",
				"字幕翻译语言":           "zh-CN",
				"empty":            "",
				"zero":             "0",
				"text":             "  keep spaces = [x],{} # literal  ",
				`quoted key "双引号"`: `both 'apostrophe' and "quotes" \ path`,
				"line":             "one\ntwo",
			},
		},
		{Name: "expanded", Link: "file:expanded"},
		{Name: "empty_arguments", Link: "file:empty"},
		{Name: "simple", Link: "file:simple"},
		{Link: "file:///var/lib/dae/anonymous"},
		{Link: "http://example.com/another.sgmodule"},
	}
	if !reflect.DeepEqual(decodedSurge(t, conf).Modules, want) {
		t.Fatalf("module sources = %#v, want %#v", decodedSurge(t, conf).Modules, want)
	}
	marshaled, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip := parseConfig(t, string(marshaled))
	if !reflect.DeepEqual(decodedSurge(t, conf), decodedSurge(t, roundTrip)) {
		t.Fatalf("module configuration changed after round trip:\nfirst: %#v\nsecond: %#v\nconfig:\n%s", decodedSurge(t, conf).Modules, decodedSurge(t, roundTrip).Modules, marshaled)
	}
}

func TestMarshalModuleArgumentsRejectInvalidSources(t *testing.T) {
	for _, test := range []struct {
		name, errorText string
		source          ModuleSource
	}{
		{
			name:      "anonymous arguments",
			source:    ModuleSource{Link: "file:test", Arguments: map[string]string{"key": "value"}},
			errorText: "require a module name",
		},
		{
			name:      "empty argument name",
			source:    ModuleSource{Name: "test", Link: "file:test", Arguments: map[string]string{" ": "value"}},
			errorText: "must be non-empty",
		},
		{
			name:      "equals in argument name",
			source:    ModuleSource{Name: "test", Link: "file:test", Arguments: map[string]string{"key=value": "other"}},
			errorText: "cannot contain '='",
		},
		{
			name:      "whitespace in argument name",
			source:    ModuleSource{Name: "test", Link: "file:test", Arguments: map[string]string{" key ": "value"}},
			errorText: "cannot have leading or trailing whitespace",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := FormatModuleSource(test.source)
			if err == nil || !strings.Contains(err.Error(), test.errorText) {
				t.Fatalf("marshal error = %v, want %q", err, test.errorText)
			}
		})
	}
}

func decodedSurge(t *testing.T, conf *config.Config) Config {
	t.Helper()
	s, err := ParseConfig(conf.Plugins[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestSurgePluginDefaultsAndLimits(t *testing.T) {
	c := parseConfig(t, `global {} plugins { surge { module { 'file:module.sgmodule' } } } routing {fallback: direct}`)
	s := decodedSurge(t, c)
	if !s.Store || s.ScriptTimeout != 5*time.Second || s.MaxBodySize != 32<<20 || s.MemoryLimit != 128<<20 || s.MaxConcurrentScripts != 16 {
		t.Fatalf("defaults: %+v", s)
	}
	for _, limit := range []string{"script_timeout: 0s", "script_timeout: 61s", "memory_limit: 1", "memory_limit: 1073741825", "max_body_size: 0", "max_body_size: 268435457", "max_concurrent_scripts: 0", "max_concurrent_scripts: 257", "ca_cert: 'x'", "client_source_address: all", "store: 'old-store.json'", "store: ''"} {
		sections, err := config_parser.Parse("surge { module { 'file:module.sgmodule' }\n" + limit + "\n}")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseConfig(sections[0]); err == nil {
			t.Errorf("accepted invalid plugin setting: %s", limit)
		}
	}
}

func parseConfig(t *testing.T, body string) *config.Config {
	t.Helper()
	sections, err := config_parser.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatal(err)
	}
	return conf
}
