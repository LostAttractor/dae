// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"reflect"
	"strings"
	"testing"
)

const youtubeArgumentModule = `#!name=YouTube 参数示例
#!desc=过滤 YouTube 广告
#!arguments=屏蔽上传按钮:true,屏蔽选段按钮:true,屏蔽Shorts按钮:false,字幕翻译语言:off,启用调试模式:false
#!arguments-desc=功能设置\n字幕翻译语言可填写 off、zh-Hans 等。\n调试模式仅影响日志。
[Script]
youtube = type=http-response,pattern=^https://youtube\.example/,script-path=youtube.js,argument="{"屏蔽上传按钮":{{{屏蔽上传按钮}}},"屏蔽选段按钮":{{{屏蔽选段按钮}}},"屏蔽Shorts按钮":{{{屏蔽Shorts按钮}}},"字幕翻译语言":"{{{字幕翻译语言}}}","启用调试模式":{{{启用调试模式}}}}"
`

func TestReadMetadataPreservesArgumentOrderAndDescription(t *testing.T) {
	metadata, err := ReadMetadata("\ufeff" + strings.ReplaceAll(youtubeArgumentModule, "\n", "\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Metadata{
		Name:                 "YouTube 参数示例",
		Description:          "过滤 YouTube 广告",
		ArgumentsDescription: "功能设置\n字幕翻译语言可填写 off、zh-Hans 等。\n调试模式仅影响日志。",
		Arguments: []Argument{
			{Name: "屏蔽上传按钮", Default: "true", HasDefault: true},
			{Name: "屏蔽选段按钮", Default: "true", HasDefault: true},
			{Name: "屏蔽Shorts按钮", Default: "false", HasDefault: true},
			{Name: "字幕翻译语言", Default: "off", HasDefault: true},
			{Name: "启用调试模式", Default: "false", HasDefault: true},
		},
	}
	if !reflect.DeepEqual(metadata, want) {
		t.Fatalf("metadata=%+v, want %+v", metadata, want)
	}
}

func TestReadMetadataDoesNotParseDirectivesOrRequireValues(t *testing.T) {
	metadata, err := ReadMetadata(`#!arguments=required,empty:,url:https://example.com:8443
[Script]
not a script directive
undefined = {{{missing}}}
`)
	if err != nil {
		t.Fatal(err)
	}
	want := []Argument{
		{Name: "required"},
		{Name: "empty", HasDefault: true},
		{Name: "url", Default: "https://example.com:8443", HasDefault: true},
	}
	if !reflect.DeepEqual(metadata.Arguments, want) {
		t.Fatalf("arguments=%+v, want %+v", metadata.Arguments, want)
	}
}

func TestModuleArgumentOverridesReplaceDefaults(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]string
		want      string
	}{
		{
			name: "defaults",
			want: `{"屏蔽上传按钮":true,"屏蔽选段按钮":true,"屏蔽Shorts按钮":false,"字幕翻译语言":"off","启用调试模式":false}`,
		},
		{
			name:      "selected overrides",
			overrides: map[string]string{"屏蔽上传按钮": "false", "屏蔽Shorts按钮": "true", "字幕翻译语言": "zh-Hans"},
			want:      `{"屏蔽上传按钮":false,"屏蔽选段按钮":true,"屏蔽Shorts按钮":true,"字幕翻译语言":"zh-Hans","启用调试模式":false}`,
		},
		{
			name:      "explicit empty",
			overrides: map[string]string{"字幕翻译语言": ""},
			want:      `{"屏蔽上传按钮":true,"屏蔽选段按钮":true,"屏蔽Shorts按钮":false,"字幕翻译语言":"","启用调试模式":false}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			module, err := Parse(youtubeArgumentModule, test.overrides)
			if err != nil {
				t.Fatal(err)
			}
			if module.Name != "YouTube 参数示例" || len(module.Scripts) != 1 || module.Scripts[0].Argument != test.want {
				t.Fatalf("unexpected module: %+v", module)
			}
		})
	}
}

func TestModuleArgumentOverrideIsLiteralText(t *testing.T) {
	contents := `#!arguments=value:default
[Script]
a = type=http-response,pattern=.,script-path=a.js,argument='{{{value}}}'
`
	for _, value := range []string{"", "  keep spaces  ", `{"name":"test","items":[1,2]}`, `a&b=2:three`, `path\nsuffix`, `{{{value}}}`} {
		module, err := Parse(contents, map[string]string{"value": value})
		if err != nil {
			t.Fatalf("value %q: %v", value, err)
		}
		if got := module.Scripts[0].Argument; got != value {
			t.Errorf("argument=%q, want literal %q", got, value)
		}
	}
}

func TestModuleArgumentRequiredAndEmptyDefaults(t *testing.T) {
	contents := `#!arguments=required,empty:
[Script]
a = type=http-response,pattern=.,script-path=a.js,argument="{{{required}}}:{{{empty}}}"
`
	if _, err := Parse(contents, nil); err == nil || !strings.Contains(err.Error(), `"required" requires a value`) {
		t.Fatalf("missing required argument: %v", err)
	}
	for _, value := range []string{"provided", ""} {
		module, err := Parse(contents, map[string]string{"required": value})
		if err != nil {
			t.Fatal(err)
		}
		if got := module.Scripts[0].Argument; got != value+":" {
			t.Fatalf("argument=%q, want %q", got, value+":")
		}
	}
}

func TestModuleArgumentCanDisableWholeLines(t *testing.T) {
	contents := `#!arguments=disable:#,optional:
[URL Rewrite]
{{{disable}}} not a valid rewrite
{{{optional}}} ^https://example\.com/ _ reject
[Script]
{{{disable}}} not a valid script
`
	for _, marker := range []string{"#", ";", "  # ", " ; "} {
		module, err := Parse(contents, map[string]string{"disable": marker})
		if err != nil {
			t.Fatal(err)
		}
		if len(module.Scripts) != 0 || len(module.URLRewrites) != 1 || len(module.Warnings) != 0 {
			t.Fatalf("marker %q: unexpected module %+v", marker, module)
		}
	}
}

func TestModuleArgumentsRejectInvalidDeclarationsAndOverrides(t *testing.T) {
	tests := []struct {
		name      string
		contents  string
		overrides map[string]string
		wantError string
	}{
		{"duplicate in list", "#!arguments=value:1,value:2", nil, "duplicate module argument"},
		{"duplicate across lines", "#!arguments=value:1\n#!arguments=value:2", nil, "duplicate module argument"},
		{"empty name", "#!arguments=:1", nil, "invalid module argument"},
		{"empty field", "#!arguments=value:1,", nil, "invalid module argument"},
		{"invalid braces", "#!arguments={value}:1", nil, "invalid module argument"},
		{"default NUL", "#!arguments=value:a\x00b", nil, "newline or NUL"},
		{"default embedded CR", "#!arguments=value:a\rb", nil, "newline or NUL"},
		{"unknown override", "#!arguments=value:1", map[string]string{"other": "2"}, "unknown module argument override"},
		{"case sensitive override", "#!arguments=Value:1", map[string]string{"value": "2"}, "unknown module argument override"},
		{"undeclared override", "[MITM]\nhostname=example.com", map[string]string{"value": "2"}, "unknown module argument override"},
		{"missing unused argument", "#!arguments=required", nil, "requires a value"},
		{"unknown placeholder", "#!arguments=value:1\n[MITM]\nhostname={{{missing}}}", nil, "undefined argument"},
		{"case sensitive placeholder", "#!arguments=value:1\n[MITM]\nhostname={{{Value}}}", nil, "undefined argument"},
		{"unknown in substituted comment", "#!arguments=disable:#\n[Script]\n{{{disable}}} {{{missing}}}", nil, "undefined argument"},
		{"override LF", "#!arguments=value:1", map[string]string{"value": "a\nb"}, "newline or NUL"},
		{"override CR", "#!arguments=value:1", map[string]string{"value": "a\rb"}, "newline or NUL"},
		{"override NUL", "#!arguments=value:1", map[string]string{"value": "a\x00b"}, "newline or NUL"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.contents, test.overrides)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error=%v, want %q", err, test.wantError)
			}
		})
	}
}

func TestReadMetadataRejectsOversizedModule(t *testing.T) {
	if _, err := ReadMetadata(strings.Repeat("#", MaxModuleBytes+1)); err == nil {
		t.Fatal("accepted oversized module")
	}
}
