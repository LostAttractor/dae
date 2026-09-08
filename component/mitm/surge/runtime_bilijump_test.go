package surge

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestRuntimeWebCompatibilityAPIs(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	source := `
      const url = new URL("../x/feed?name=%E4%B8%AD%E6%96%87&s_locale=en", "https://GRPC.biliapi.net/a/b");
      if(url.pathname !== "/x/feed" || url.searchParams.get("name") !== "中文") throw Error("URL parse");
      url.hostname = "app.bilibili.com";
      url.searchParams.set("s_locale", "zh-Hans_CN");
      if(url.toString() !== "https://app.bilibili.com/x/feed?name=%E4%B8%AD%E6%96%87&s_locale=zh-Hans_CN") throw Error(url.toString());
      const headers = $request.headers;
      if(headers["x-bili-moss-engine-type"] !== "1" || !Object.hasOwn(headers,"content-type")) throw Error("header lookup");
      headers["CONTENT-type"]="application/grpc";
      if(Object.keys(headers).filter(key => key.toLowerCase()==="content-type").length !== 1) throw Error("duplicate header");
      delete headers["content-TYPE"];
      if("Content-Type" in headers) throw Error("header deletion");
      const doc=new DOMParser().parseFromString("<title>test</title><main>original</main>","text/html");
      const script=doc.createElement("script"); script.textContent="globalThis.onlyInClient=true"; doc.head.appendChild(script);
      if(typeof onlyInClient!=="undefined") throw Error("HTML parser executed script");
      $done({body:doc.documentElement.outerHTML, headers, h2_trailers:{"grpc-status":"0"}});
    `
	result, err := r.Run(context.Background(), source, Invocation{Request: &Message{Headers: map[string]string{"X-Bili-Moss-Engine-Type": "1", "Content-Type": "text/plain"}}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Body == nil || !strings.Contains(string(result.Body.Bytes()), "<head><title>test</title><script>globalThis.onlyInClient=true</script></head>") || result.Trailers["grpc-status"] != "0" {
		t.Fatalf("unexpected compatibility result: %#v", result)
	}
}

func TestRuntimeWebResourceLimits(t *testing.T) {
	data := gzipFixture(t, bytes.Repeat([]byte("x"), 8192))
	_, err := runtimeUngzip(context.Background(), base64.StdEncoding.EncodeToString(data), 1024)
	if err == nil || !strings.Contains(err.Error(), "output exceeds") {
		t.Fatalf("gzip expansion was not bounded: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = runtimeUngzip(ctx, base64.StdEncoding.EncodeToString(data), 16384)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("gzip ignored cancellation: %v", err)
	}
	dom := newRuntimeDOM(context.Background(), 1024)
	if _, err := dom.call("parse", strings.Repeat("x", 2048), ""); err == nil {
		t.Fatal("HTML input was not bounded")
	}
	dom = newRuntimeDOM(context.Background(), 1<<20)
	if _, err := dom.call("parse", strings.Repeat("<i></i>", runtimeDOMMaxNodes), ""); err == nil {
		t.Fatal("DOM node count was not bounded")
	}
	dom = newRuntimeDOM(context.Background(), 100)
	id, err := dom.call("parse", `<p a="&quot;&quot;&quot;">hello</p>`, "")
	if err != nil {
		t.Fatal(err)
	}
	// HTML serialization may expand escapes; the writer must bound that too.
	dom.limit = 10
	if _, err := dom.call("outerHTML", id.(string), ""); err == nil {
		t.Fatal("HTML serialization was not bounded")
	}
}

// Downloaded scripts remain outside the repository. These tests exercise the
// exact upstream code with deterministic data and a fake HTTP transport; no
// Bilibili or Cloudflare request is sent during compatibility validation.
func TestRuntimeBilijumpCompatibility(t *testing.T) {
	dir := os.Getenv("DAE_SURGE_BILIJUMP_FIXTURES")
	if dir == "" {
		t.Skip("set DAE_SURGE_BILIJUMP_FIXTURES to the directory containing the upstream scripts")
	}
	load := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	run := func(t *testing.T, name string, in Invocation) *Result {
		t.Helper()
		var logs []string
		r := testRuntime(t, RuntimeOptions{Logger: testSurgeLogger(func(e *log.Entry) { logs = append(logs, e.Message) })})
		out, err := r.Run(context.Background(), load(name), in)
		if err != nil {
			t.Fatalf("%s: %v; logs %v", name, err, logs)
		}
		if out.Body == nil && out.Response == nil {
			t.Fatalf("%s did not transform the fixture; logs %v", name, logs)
		}
		if len(logs) > 0 {
			t.Fatalf("%s logged a script failure: %v", name, logs)
		}
		return out
	}
	t.Run("json-feed", func(t *testing.T) {
		out := run(t, "bilibili.json.js", Invocation{
			Request:  &Message{URL: "https://app.bilibili.com/x/v2/feed/index?build=999", Method: "GET"},
			Response: &Message{Status: 200, Body: []byte(`{"code":0,"data":{"items":[{"id":1,"card_type":"small_cover_v2","card_goto":"av"},{"id":2,"card_type":"large_cover_v1","card_goto":"av","ad_info":{"id":1}},{"id":3,"card_type":"large_cover_v1","card_goto":"av","banner_item":{}}]}}`)},
		})
		if !bytes.Contains(out.Body.Bytes(), []byte(`"id":1`)) || bytes.Contains(out.Body.Bytes(), []byte(`"id":2`)) || bytes.Contains(out.Body.Bytes(), []byte(`"id":3`)) {
			t.Fatalf("feed filter failed: %s", out.Body.Bytes())
		}
	})
	t.Run("json-localized-tabs", func(t *testing.T) {
		out := run(t, "bilibili.json.js", Invocation{
			Request:  &Message{URL: "https://app.bilibili.com/x/resource/show/tab/v2?s_locale=en", Method: "GET"},
			Response: &Message{Status: 200, Body: []byte(`{"code":0,"data":{"tab":[{"name":"old"}],"bottom":[]}}`)},
		})
		if bytes.Contains(out.Body.Bytes(), []byte(`"old"`)) || !bytes.Contains(out.Body.Bytes(), []byte(`"Live"`)) {
			t.Fatalf("localized tab rewrite failed: %s", out.Body.Bytes())
		}
	})
	t.Run("live-feed", func(t *testing.T) {
		out := run(t, "bilibili.json.js", Invocation{
			Request:  &Message{URL: "https://api.live.bilibili.com/xlive/app-interface/v2/index/feed?build=999", Method: "GET"},
			Response: &Message{Status: 200, Body: []byte(`{"code":0,"data":{"card_list":[{"card_type":"banner_v2"},{"card_type":"activity_card_v1"},{"card_type":"small_card","room_id":42}]}}`)},
		})
		if !bytes.Contains(out.Body.Bytes(), []byte(`"room_id":42`)) || bytes.Contains(out.Body.Bytes(), []byte(`banner_v2`)) {
			t.Fatalf("live feed rewrite failed: %s", out.Body.Bytes())
		}
	})
	t.Run("skin", func(t *testing.T) {
		out := run(t, "bili-suit-diy.js", Invocation{Response: &Message{Status: 200, Body: []byte(`{"data":{"common_equip":{"id":1},"user_equip":{"id":42}}}`)}})
		if bytes.Contains(out.Body.Bytes(), []byte("common_equip")) || !bytes.Contains(out.Body.Bytes(), []byte(`"id":42`)) {
			t.Fatalf("skin rewrite failed: %s", out.Body.Bytes())
		}
	})
	t.Run("webpage", func(t *testing.T) {
		out := run(t, "webpage.bilibili.js", Invocation{
			Request:  &Message{URL: "https://www.bilibili.com/blackboard/era/example.html?x=1", Method: "GET"},
			Response: &Message{Status: 200, Body: []byte(`<!doctype html><html><head><title>Activity</title></head><body><main id="video">Keep this</main></body></html>`)},
		})
		body := string(out.Body.Bytes())
		if !strings.Contains(body, `__BILIACT_EVAPAGEDATA__`) || !strings.Contains(body, `<main id="video">Keep this</main>`) || strings.Index(body, "<script>") > strings.Index(body, "</head>") {
			t.Fatalf("webpage injection failed: %s", body)
		}
	})
	t.Run("protobuf-gzip", func(t *testing.T) {
		// DmViewReply activity_meta (18) and qoe (25) are stripped; unknown
		// field 1 is retained. Exercise the real gRPC gzip branch as well.
		payload := append([]byte{8, 7}, wireBytes(18, []byte("promotion"))...)
		payload = append(payload, wireBytes(25, []byte("qoe-data"))...)
		out := run(t, "bilibili.protobuf.response.js", Invocation{
			Request:        &Message{URL: "https://grpc.biliapi.net/bilibili.community.service.dm.v1.DM/DmView", Method: "POST", Headers: map[string]string{"X-Bili-Moss-Engine-Type": "1"}},
			Response:       &Message{Status: 200, Body: grpcFixture(gzipFixture(t, payload), true), Headers: map[string]string{"Content-Type": "application/grpc"}},
			BinaryBodyMode: true,
		})
		if !bytes.Equal(out.Body.Bytes(), grpcFixture([]byte{8, 7}, false)) || out.Headers["grpc-status"] != "0" {
			t.Fatalf("gRPC rewrite failed: %#v %x", out, out.Body.Bytes())
		}
	})
	t.Run("request-fetch-and-filter", func(t *testing.T) {
		good := wireBytes(14, wireBytes(12, wireBytes(1, []byte("ordinary comment"))))
		ad := wireBytes(14, wireBytes(12, wireBytes(1, []byte("https://b23.tv/cm/example"))))
		payload := append(wireBytes(11, []byte("ad-metadata")), good...)
		payload = append(payload, ad...)
		var calls atomic.Int32
		client := &http.Client{Transport: runtimeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls.Add(1)
			if req.URL.Hostname() != "grpc.biliapi.net" || req.Method != "POST" {
				return nil, fmt.Errorf("unexpected fixture request")
			}
			return fixtureHTTPResponse(grpcFixture(gzipFixture(t, payload), true), true), nil
		})}
		out := run(t, "bilijump.protobuf.request.js", Invocation{
			Request:        &Message{URL: "https://grpc.biliapi.net/bilibili.main.community.reply.v1.Reply/MainList", Method: "POST", Headers: map[string]string{"Content-Type": "application/grpc"}, Body: grpcFixture([]byte{8, 1}, false)},
			BinaryBodyMode: true, HTTPClient: client, Argument: `{"purifyComment":true,"logLevel":4}`,
		})
		if calls.Load() != 1 || out.Response == nil || out.Response.Body == nil || !bytes.Equal(out.Response.Body.Bytes(), grpcFixture(good, false)) || out.Response.Trailers["Grpc-Status"] != "0" {
			t.Fatalf("request rewrite failed: %#v", out)
		}
	})
	t.Run("airborne", func(t *testing.T) {
		// Valid DmSegMobileReq pid=100, oid=200, type=1, segment_index=1.
		requestBody := grpcFixture(gzipFixture(t, []byte{8, 100, 16, 200, 1, 24, 1, 32, 1}), true)
		existing := wireBytes(1, append([]byte{8, 42}, wireBytes(7, []byte("existing danmaku"))...))
		var calls atomic.Int32
		client := &http.Client{Transport: runtimeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls.Add(1)
			switch req.URL.Hostname() {
			case "grpc.biliapi.net":
				body, err := io.ReadAll(req.Body)
				if err != nil || !bytes.Equal(body, requestBody) {
					return nil, errors.New("upstream request body changed")
				}
				return fixtureHTTPResponse(grpcFixture(existing, false), true), nil
			case "api.cloudflare.com":
				var query struct {
					Params []string `json:"params"`
				}
				if err := json.NewDecoder(req.Body).Decode(&query); err != nil || len(query.Params) != 1 || query.Params[0] != "200" {
					return nil, errors.New("unexpected fixture query")
				}
				return fixtureHTTPResponse([]byte(`{"result":[{"results":[{"data":"{\"ads\":[{\"start_time\":\"10\",\"end_time\":\"20\"}]}"}]}]}`), false), nil
			default:
				return nil, errors.New("unexpected external request blocked by test")
			}
		})}
		out := run(t, "bilijump.protobuf.request.js", Invocation{
			Request:    &Message{URL: "https://grpc.biliapi.net/bilibili.community.service.dm.v1.DM/DmSegMobile", Method: "POST", Body: requestBody, Headers: map[string]string{"Content-Type": "application/grpc"}},
			HTTPClient: client, BinaryBodyMode: true, Argument: `{"logLevel":4}`,
		})
		if calls.Load() != 2 || out.Response == nil || out.Response.Body == nil {
			t.Fatalf("airborne did not fetch both fixtures: %#v calls %d", out, calls.Load())
		}
		body := out.Response.Body.Bytes()
		if len(body) < 5 || int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5 || !bytes.Contains(body, []byte("existing danmaku")) || !bytes.Contains(body, []byte("airborne:20000")) || !bytes.Contains(body, []byte("00:10-00:20")) {
			t.Fatalf("airborne protobuf did not retain/add expected elements: %x", body)
		}
	})
}

type runtimeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f runtimeRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fixtureHTTPResponse(body []byte, grpc bool) *http.Response {
	r := &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}
	if grpc {
		r.Header.Set("Content-Type", "application/grpc")
		r.Trailer = http.Header{"Grpc-Status": []string{"0"}}
	} else {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

func gzipFixture(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func grpcFixture(data []byte, compressed bool) []byte {
	out := make([]byte, len(data)+5)
	if compressed {
		out[0] = 1
	}
	binary.BigEndian.PutUint32(out[1:5], uint32(len(data)))
	copy(out[5:], data)
	return out
}

func wireBytes(field protowire.Number, data []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, field, protowire.BytesType), data)
}
