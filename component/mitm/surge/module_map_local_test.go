// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMapLocalTextAndBinary(t *testing.T) {
	m, err := Parse(`[Map Local]
^https://example.com/json header="content-type: application/json|x-example: yes" data-type=text data="{"code":0,"message":"hello world","data":{"items":[]}}"
^https://example.com/grpc data-type=base64 data="AAAAAAA=" header="content-type: application/grpc|grpc-status: 0"
^https://example.com/empty data-type=text data="" status-code=204
^https://example.com/gif data-type=tiny-gif
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Warnings) != 0 || len(m.MapLocals) != 4 {
		t.Fatalf("Map Local parsing: %+v", m)
	}
	e := &Engine{options: EngineOptions{Modules: []*Module{m}, MaxBodySize: 1 << 20}}
	for _, test := range []struct {
		path, contentType, body string
		status                  int
	}{
		{"json", "application/json", `{"code":0,"message":"hello world","data":{"items":[]}}`, 200},
		{"grpc", "application/grpc", "\x00\x00\x00\x00\x00", 200},
		{"empty", "text/plain", "", 204},
	} {
		req, _ := http.NewRequest("GET", "https://example.com/"+test.path, nil)
		resp, err := e.mapLocal(req)
		if err != nil || resp == nil {
			t.Fatalf("%s: response=%v, err=%v", test.path, resp, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != test.body || resp.StatusCode != test.status || resp.Header.Get("Content-Type") != test.contentType {
			t.Fatalf("%s: body=%q response=%+v", test.path, body, resp)
		}
		if test.path == "grpc" && resp.Header.Get("Grpc-Status") != "0" {
			t.Fatal("gRPC status was not preserved")
		}
		resp.Header.Set("Content-Type", "changed")
		if m.MapLocals[0].Header.Get("Content-Type") != "application/json" {
			t.Fatal("response headers share mutable module state")
		}
	}
	if !bytes.HasPrefix(m.MapLocals[3].Body, []byte("GIF89a")) {
		t.Fatal("tiny-gif does not contain a GIF")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte("Content-Type: application/json\r\nX-Test: yes"))
	m, err = Parse("[Map Local]\n. data-type=text data=\"{}\" header="+encoded, nil)
	if err != nil || m.MapLocals[0].Header.Get("X-Test") != "yes" {
		t.Fatalf("base64 headers: %v", err)
	}
	m, err = Parse("[Map Local]\n. data=https://example.com/response.json?version=1", nil)
	if err != nil || m.MapLocals[0].Header.Get("Content-Type") != "application/json" {
		t.Fatalf("file URL content type: module=%v err=%v", m, err)
	}
}

func TestMapLocalRejectsInvalidConfiguration(t *testing.T) {
	for _, line := range []string{
		`. data-type=base64 data="not-base64"`,
		`. data-type=text data="unterminated`,
		`. data-type=text data=a data=b`,
		`. data-type=file`,
		`. data-type=text data="" status-code=199`,
		`. data-type=text data="" status-code=1000`,
		`. data-type=text header="Content-Length: 100"`,
		`. data-type=text header="Transfer-Encoding: chunked"`,
		`. data-type=text header="bad header: yes"`,
		`. data-type=text header="X-Test: a\r\nb"`,
	} {
		if _, err := Parse("[Map Local]\n"+line, nil); err == nil {
			t.Errorf("accepted %s", line)
		}
	}
}

func TestMapLocalLoadsRelativeFileAndBoundsBody(t *testing.T) {
	dir := t.TempDir()
	modulePath := filepath.Join(dir, "example.sgmodule")
	for name, contents := range map[string]string{
		"example.sgmodule": "[Map Local]\n^https://example.com/ data=data.json\n^https://example.net/ data=data.json\n",
		"data.json":        `{"ok":true}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	m, err := Load(context.Background(), "file://"+modulePath, nil, LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(m.MapLocals[0].Body) != `{"ok":true}` || m.MapLocals[0].Header.Get("Content-Type") != "application/json" {
		t.Fatalf("file not loaded: %+v", m.MapLocals[0])
	}
	if &m.MapLocals[0].Body[0] != &m.MapLocals[1].Body[0] {
		t.Fatal("repeated file references must share their immutable body")
	}
	e := &Engine{options: EngineOptions{Modules: []*Module{m}, MaxBodySize: 1}}
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	if _, err := e.mapLocal(req); err != errBodyTooLarge {
		t.Fatalf("body cap not enforced: %v", err)
	}
}

// Use an unmodified checkout/download so changes to the real module can be
// checked without vendoring externally maintained scripts or requiring CI I/O.
func TestBilijumpModuleMapLocalCompatibility(t *testing.T) {
	dir := os.Getenv("DAE_SURGE_BILIJUMP_FIXTURES")
	if dir == "" {
		t.Skip("set DAE_SURGE_BILIJUMP_FIXTURES to a directory containing bilijump.sgmodule")
	}
	source, err := os.ReadFile(filepath.Join(dir, "bilijump.sgmodule"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(string(source), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.MapLocals) != 7 || len(m.BodyRewrites) != 4 || len(m.Rules) != 6 || len(m.Scripts) != 8 {
		t.Fatalf("unexpected module counts: map=%d body=%d rules=%d scripts=%d", len(m.MapLocals), len(m.BodyRewrites), len(m.Rules), len(m.Scripts))
	}
	for _, warning := range m.Warnings {
		if strings.Contains(warning, "unsupported section") || strings.Contains(warning, `unsupported parameter "engine"`) {
			t.Errorf("unhandled Bilijump directive: %s", warning)
		}
	}
	e := &Engine{options: EngineOptions{Modules: []*Module{m}, MaxBodySize: 1 << 20}}
	for _, test := range []struct{ url, body string }{
		{"https://api.bilibili.com/x/resource/top/activity?x=1", `{"code":-404,"message":"-404","ttl":1,"data":null}`},
		{"https://api.bilibili.com/pgc/activity/deliver/material/receive?x=1", `{"code":0,"data":{"closeType":"close_win","container":[],"showTime":""},"message":"success"}`},
		{"https://api.live.bilibili.com/xlive/e-commerce-interface/v1/ecommerce-user/get_shopping_info?x=1", `{}`},
		{"https://line3-h5-mobile-api.biligame.com/game/live/large_card_material?x=1", `{"code":0,"message":"success"}`},
		{"https://grpc.biliapi.net/bilibili.app.interface.v1.Teenagers/ModeStatus", "AAAAABMKEQgCEgl0ZWVuYWdlcnMgAioA"},
		{"https://grpc.biliapi.net/bilibili.app.interface.v1.Search/DefaultWords", "AAAAACEaHeaQnOe0ouinhumikeOAgeeVquWJp+aIlnVw5Li7KAE="},
		{"https://grpc.biliapi.net/bilibili.app.viewunite.v1.View/PlayPause", "AAAAAAA="},
	} {
		req, _ := http.NewRequest("POST", test.url, nil)
		resp, err := e.mapLocal(req)
		if err != nil || resp == nil {
			t.Fatalf("%s: response=%v err=%v", test.url, resp, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		want := []byte(test.body)
		if strings.Contains(test.url, "grpc.biliapi.net") {
			want, err = base64.StdEncoding.DecodeString(test.body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Header.Get("Grpc-Status") != "0" {
				t.Fatal("missing gRPC success status")
			}
		}
		if !bytes.Equal(body, want) {
			t.Fatalf("%s: response body %q, want %q", test.url, body, want)
		}
	}
}
