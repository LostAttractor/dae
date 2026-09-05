package config

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestSurgeConfigDefaultsAndRoundTrip(t *testing.T) {
	conf := parseConfig(t, `global {}
surge {
  enabled: true
  module {
    example: 'file:modules/example.sgmodule'
    'https://example.com/remote.sgmodule'
  }
  ca_cert: 'mitm-ca.pem'
  ca_key: 'mitm-ca.key'
  store: 'surge-store.json'
}
routing { fallback: direct }
`)
	if !conf.Surge.Enabled || conf.Global.APIPort != 0 || len(conf.Surge.Modules) != 2 || conf.Surge.ScriptTimeout != 5*time.Second || conf.Surge.MemoryLimit != 128<<20 || conf.Surge.MaxBodySize != 32<<20 || conf.Surge.MaxConcurrentScripts != 16 {
		t.Fatalf("unexpected Surge config defaults: %+v", conf.Surge)
	}
	if conf.Surge.ClientSourceAddress != nil {
		t.Fatalf("omitted client_source_address should remain unspecified: %v", conf.Surge.ClientSourceAddress)
	}
	marshaled, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip := parseConfig(t, string(marshaled))
	if !reflect.DeepEqual(conf, roundTrip) {
		t.Fatalf("Surge configuration changed after round trip:\nfirst: %+v\nsecond: %+v", conf.Surge, roundTrip.Surge)
	}
}

func TestSurgeConfigRemainsDisabledWhenAbsent(t *testing.T) {
	conf := parseConfig(t, "global {}\nrouting { fallback: direct }")
	if conf.Surge.Enabled {
		t.Fatal("Surge was enabled without a configuration section")
	}
	marshaled, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip := parseConfig(t, string(marshaled))
	if !reflect.DeepEqual(conf.Surge, roundTrip.Surge) {
		t.Fatalf("absent Surge settings changed after round trip: %+v -> %+v", conf.Surge, roundTrip.Surge)
	}
}

func TestSurgeConfigRejectsUnsafeLimitsAndIncompleteCA(t *testing.T) {
	for _, invalid := range []string{
		"enabled: true",
		"enabled: true\nmodule { 'file:module.sgmodule' }\nca_cert: 'ca.pem'",
		"enabled: true\nmodule { 'file:module.sgmodule' }\nca_key: 'ca.key'",
	} {
		t.Run(invalid, func(t *testing.T) {
			sections, err := config_parser.Parse("global {}\nsurge {\n" + invalid + "\n}\nrouting { fallback: direct }")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(sections); err == nil {
				t.Fatal("accepted incomplete enabled Surge configuration")
			}
		})
	}
	for _, limit := range []string{
		"script_timeout: 0s", "script_timeout: 61s",
		"memory_limit: 1", "memory_limit: 1073741825",
		"max_body_size: 0", "max_body_size: 268435457",
		"max_concurrent_scripts: 0", "max_concurrent_scripts: 257",
	} {
		t.Run(limit, func(t *testing.T) {
			sections, err := config_parser.Parse("global {}\nsurge {\nenabled: true\nmodule { 'file:module.sgmodule' }\nca_cert: 'ca.pem'\nca_key: 'ca.key'\n" + limit + "\n}\nrouting { fallback: direct }")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(sections); err == nil {
				t.Fatal("accepted invalid Surge resource limit")
			}
		})
	}
}

func TestSurgeConfigClientSourceAddressListsAndRoundTrip(t *testing.T) {
	conf := parseConfig(t, `global { api_port: 9080 }
surge {
  enabled: true
  module { 'file:module.sgmodule' }
  ca_cert: 'ca.pem'
  ca_key: 'ca.key'
  client_source_address: '-192.168.1.50,192.168.1.0/24'
  client_source_address: '-02:00:00:00:00:10,2001:db8::/64'
  client_source_address: '02:00:00:00:00:20'
  client_source_address: 'all'
}
routing { fallback: direct }
`)
	if conf.Global.APIPort != 9080 {
		t.Fatalf("api_port = %d, want 9080", conf.Global.APIPort)
	}
	want := []string{"-192.168.1.50", "192.168.1.0/24", "-02:00:00:00:00:10", "2001:db8::/64", "02:00:00:00:00:20", "all"}
	if !reflect.DeepEqual(conf.Surge.ClientSourceAddress, want) {
		t.Fatalf("comma-separated and repeated entries lost order: %v", conf.Surge.ClientSourceAddress)
	}
	marshaled, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip := parseConfig(t, string(marshaled))
	if !reflect.DeepEqual(conf, roundTrip) {
		t.Fatalf("source address configuration changed after round trip: %v -> %v", conf.Surge.ClientSourceAddress, roundTrip.Surge.ClientSourceAddress)
	}

}

func TestSurgeConfigRejectsInvalidClientSourceAddress(t *testing.T) {
	for _, source := range []string{
		"", "192.168.1.5,", "example.com",
	} {
		t.Run(source, func(t *testing.T) {
			sections, err := config_parser.Parse("global {}\nsurge {\nenabled: true\nmodule { 'file:module.sgmodule' }\nca_cert: 'ca.pem'\nca_key: 'ca.key'\nclient_source_address: '" + source + "'\n}\nrouting { fallback: direct }")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(sections); err == nil || !strings.Contains(err.Error(), "surge.client_source_address") {
				t.Fatalf("invalid source %q must identify the setting: %v", source, err)
			}
		})
	}
}

func TestSurgeConfigDisabledSourceAddressIsNotValidated(t *testing.T) {
	conf := parseConfig(t, "global {}\nsurge { enabled: false\nclient_source_address: 'example.com' }\nrouting { fallback: direct }")
	if conf.Surge.Enabled || !reflect.DeepEqual(conf.Surge.ClientSourceAddress, []string{"example.com"}) {
		t.Fatalf("disabled Surge configuration was changed: %+v", conf.Surge)
	}
}

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
			sections, err := config_parser.Parse("global {}\nsurge {\n" + test.body + "\n}\nrouting { fallback: direct }")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(sections); err == nil || !strings.Contains(err.Error(), test.errorText) {
				t.Fatalf("parse error = %v, want %q", err, test.errorText)
			}
		})
	}
}

func TestSurgeModuleSourcesAndArgumentsRoundTrip(t *testing.T) {
	conf := parseConfig(t, `global {}
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
      link: 'https-file://example.com/youtube.sgmodule?token=a=b,c'
    }
    expanded { link: 'file:expanded' }
    empty_arguments { link: 'file:empty' arguments {} }
    simple: 'file:simple'
    'file:///var/lib/dae/anonymous'
  }
  module { 'http://example.com/another.sgmodule' }
}
routing { fallback: direct }
`)
	want := []ModuleSource{
		{
			Name: "youtube",
			Link: "https-file://example.com/youtube.sgmodule?token=a=b,c",
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
	if !reflect.DeepEqual(conf.Surge.Modules, want) {
		t.Fatalf("module sources = %#v, want %#v", conf.Surge.Modules, want)
	}
	marshaled, err := conf.Marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip := parseConfig(t, string(marshaled))
	if !reflect.DeepEqual(conf, roundTrip) {
		t.Fatalf("module configuration changed after round trip:\nfirst: %#v\nsecond: %#v\nconfig:\n%s", conf.Surge.Modules, roundTrip.Surge.Modules, marshaled)
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
			m := Marshaller{IndentSpace: 2}
			err := m.MarshalSection("module", reflect.ValueOf([]ModuleSource{test.source}), 0)
			if err == nil || !strings.Contains(err.Error(), test.errorText) {
				t.Fatalf("marshal error = %v, want %q", err, test.errorText)
			}
		})
	}
}
