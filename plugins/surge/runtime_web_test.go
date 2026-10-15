// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestRuntimeWebCompatibilityAPIs(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	source := `
      const url = new URL("../x/feed?name=%E4%B8%AD%E6%96%87&s_locale=en", "https://API.EXAMPLE.TEST/a/b");
      if(url.pathname !== "/x/feed" || url.searchParams.get("name") !== "中文") throw Error("URL parse");
      url.hostname = "example.test";
      url.searchParams.set("s_locale", "zh-Hans_CN");
      if(url.toString() !== "https://example.test/x/feed?name=%E4%B8%AD%E6%96%87&s_locale=zh-Hans_CN") throw Error(url.toString());
      const headers = $request.headers;
      if(headers["x-example-mode"] !== "1" || !Object.hasOwn(headers,"content-type")) throw Error("header lookup");
      headers["CONTENT-type"]="application/grpc";
      if(Object.keys(headers).filter(key => key.toLowerCase()==="content-type").length !== 1) throw Error("duplicate header");
      delete headers["content-TYPE"];
      if("Content-Type" in headers) throw Error("header deletion");
      const doc=new DOMParser().parseFromString("<title>test</title><main>original</main>","text/html");
      const script=doc.createElement("script"); script.textContent="globalThis.onlyInClient=true"; doc.head.appendChild(script);
      if(typeof onlyInClient!=="undefined") throw Error("HTML parser executed script");
      $done({body:doc.documentElement.outerHTML, headers, h2_trailers:{"grpc-status":"0"}});
    `
	result, err := r.Run(context.Background(), source, Invocation{Request: &Message{Headers: http.Header{"X-Example-Mode": {"1"}, "Content-Type": {"text/plain"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Body == nil || !strings.Contains(string(result.Body.Bytes()), "<head><title>test</title><script>globalThis.onlyInClient=true</script></head>") || result.Trailers.Get("Grpc-Status") != "0" {
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

func TestRuntimeJSONTransformFixture(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	result, err := r.Run(t.Context(), `const value=JSON.parse($response.body); value.items=value.items.filter(item=>item.keep); $done({body:JSON.stringify(value)});`, Invocation{Response: &Message{Status: 200, Body: []byte(`{"items":[{"id":1,"keep":true},{"id":2,"keep":false}]}`)}, ScriptType: "http-response"})
	if err != nil || result.Body == nil || string(result.Body.Bytes()) != `{"items":[{"id":1,"keep":true}]}` {
		t.Fatalf("JSON transform: %#v %v", result, err)
	}
}

type runtimeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f runtimeRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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

func TestRuntimeURLSearchParamsContracts(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	result, err := r.Run(t.Context(), `
function assert(value) { if (!value) throw Error("URLSearchParams contract"); }
const p = new URLSearchParams("q=100%&bad=%C3%28&bom=%EF%BB%BFx&a=1&a=2");
assert(p.get("q") === "100%" && p.get("bad") === "\uFFFD(" && p.get("bom") === "\uFEFFx");
p.delete("a", "1"); assert(p.getAll("a").join() === "2" && !p.has("a", "1") && p.has("a", "2"));
const live = new URLSearchParams("a=1&b=2"), iterator = live.entries();
assert(iterator.next().value.join() === "a,1");
live.delete("a"); live.append("c", "3");
assert(iterator.next().value.join() === "c,3");
const unicode = new URLSearchParams({x:"\uD800"});
assert(unicode.toString() === "x=%EF%BF%BD");
assert(new URLSearchParams(null).size === 0);
$done();`, Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	result.Close()
}
