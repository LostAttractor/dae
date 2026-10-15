// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuntimeFetchUsesInvocationBudget(t *testing.T) {
	runtimeFakeClockTest(t, func(t *testing.T) {
		client := &http.Client{Transport: runtimeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(6 * time.Second):
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody}, nil
			}
		})}
		r := testRuntime(t, RuntimeOptions{Timeout: 10 * time.Second})
		result, err := r.Run(t.Context(), `fetch("https://example.test/").then(() => $done(), e => $done({body:String(e)}));`, Invocation{HTTPClient: client})
		if err != nil {
			t.Fatal(err)
		}
		defer result.Close()
		if result.Body != nil {
			t.Fatalf("fetch inherited a shorter HTTP timeout: %s", result.Body.Bytes())
		}
	})
}

func TestRuntimeFetch(t *testing.T) {
	var redirects atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/redirect":
			http.Redirect(w, req, "/json", http.StatusFound)
		case "/json":
			redirects.Add(1)
			w.Header().Add("Set-Cookie", "one=1; Path=/")
			w.Header().Add("Set-Cookie", "two=2; Path=/")
			fmt.Fprint(w, `{"value":"中文"}`)
		case "/echo":
			w.Header().Set("Content-Type", req.Header.Get("Content-Type"))
			w.Header().Set("X-Cookie", req.Header.Get("Cookie"))
			io.Copy(w, req.Body)
		case "/empty":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	r := testRuntime(t, RuntimeOptions{Timeout: time.Second})
	source := fmt.Sprintf(`(async () => {
const base = %q;
function assert(ok, message) { if (!ok) throw Error(message); }
const headers = new Headers([["X-Test", " one "], ["x-test", "two"]]);
assert(headers.get("X-TEST") === "one, two" && [...headers].length === 1, "headers");
headers.set("X-Test", "three"); headers.delete("missing");
const initial = new Request(base + "/echo", {method:"post", headers, body:new URLSearchParams({q:"中文"})});
const copied = initial.clone();
assert(!initial.bodyUsed && await copied.text() === "q=%%E4%%B8%%AD%%E6%%96%%87", "request clone");
const echoed = await fetch(initial);
assert(initial.bodyUsed && echoed.headers.get("content-type").startsWith("application/x-www-form-urlencoded"), "request metadata");
assert(await echoed.text() === "q=%%E4%%B8%%AD%%E6%%96%%87", "form body");
const response = await fetch(base + "/redirect", {credentials:"include"});
assert(response.ok && response.status === 200 && response.statusText === "OK" && response.redirected && response.url === base + "/json", "response metadata");
assert(response.headers.getSetCookie().length === 2, "set-cookie");
const clone = response.clone();
for (const item of [response, clone]) {
  let immutable = false;
  try { item.headers.set("X-Test", "value"); } catch (e) { immutable = e instanceof TypeError; }
  assert(immutable, "network response headers mutable");
  item.status = 404; item.url = "changed";
  assert(item.status === 200 && item.url === base + "/json", "response metadata writable");
}
assert((await response.json()).value === "中文" && response.bodyUsed, "json");
assert((await clone.text()).includes("中文"), "response clone");
let reused = false; try { await response.text(); } catch (e) { reused = e instanceof TypeError; }
assert(reused, "body reused");
const cookies = await fetch(base + "/echo", {credentials:"include"});
assert(cookies.headers.get("x-cookie") === "one=1; two=2", "cookie jar");
const noCookies = await fetch(base + "/echo");
assert(noCookies.headers.get("x-cookie") === "", "default cookie isolation");
const binary = new Uint8Array([9,0,255,8]);
const binaryResponse = await fetch(base + "/echo", {method:"POST", body:binary.subarray(1,3)});
assert([...new Uint8Array(await binaryResponse.arrayBuffer())].join() === "0,255", "binary body offset");
const manual = await fetch(base + "/redirect", {redirect:"manual"});
assert(manual.status === 302 && !manual.redirected && manual.headers.get("location") === "/json", "manual redirect");
let rejected = false; try { await fetch(base + "/redirect", {redirect:"error"}); } catch (e) { rejected = e instanceof TypeError; }
assert(rejected, "redirect error");
const missing = await fetch(base + "/missing");
assert(!missing.ok && missing.status === 404, "HTTP error resolved");
const empty = await fetch(base + "/empty");
assert(await empty.text() === "" && !empty.bodyUsed, "null body");
assert((await Response.json({ok:true}).json()).ok, "Response.json");
assert(await new Response(123).text() === "123", "scalar body conversion");
const custom = await fetch(base + "/echo", {method:"PROPFIND", body:{value:1}});
assert(await custom.text() === "[object Object]", "custom method/body");
let credentials = false;
try { new Request("https://user:pass@example.com/"); } catch (e) { credentials = e instanceof TypeError; }
assert(credentials, "credential URL accepted");
for (const init of [{method:"GET",body:"x"}, {signal:{}}, {body:{}}, {method:"TRACE"}]) {
  let failed = false; try { await fetch(base, init); } catch (e) { failed = e instanceof TypeError; }
  assert(failed, "unsupported request accepted");
}
$done();
})().catch(error => $done({body:String(error)}));`, server.URL)
	result, err := r.Run(t.Context(), source, Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if result.Body != nil || redirects.Load() != 1 {
		t.Fatalf("fetch contract: %q, redirect target requests=%d", result.Body.Bytes(), redirects.Load())
	}
}

func TestRuntimeFetchCancellation(t *testing.T) {
	cancelled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-req.Context().Done()
		close(cancelled)
	}))
	defer server.Close()
	r := testRuntime(t, RuntimeOptions{Timeout: time.Second})
	result, err := r.Run(t.Context(), fmt.Sprintf(`fetch(%q, {timeout:0.02}).then(() => $done({body:"unexpected success"}), e => $done({body:e instanceof TypeError ? "cancelled" : "wrong error"}));`, server.URL), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if string(result.Body.Bytes()) != "cancelled" {
		t.Fatalf("fetch timeout: %s", result.Body.Bytes())
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("timed out fetch left the network request running")
	}
}

func TestRuntimeFetchAbortSignal(t *testing.T) {
	started, cancelled := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/slow":
			close(started)
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-req.Context().Done()
			close(cancelled)
		case "/ready":
			select {
			case <-started:
			case <-req.Context().Done():
			}
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	defer server.Close()
	r := testRuntime(t, RuntimeOptions{Timeout: 2 * time.Second})
	result, err := r.Run(t.Context(), fmt.Sprintf(`(async () => {
const base = %q;
function assert(ok, text) { if (!ok) throw Error(text); }
const controller = new AbortController(), reason = {cause:"requested"};
let events = 0;
controller.signal.addEventListener("abort", () => events++, {once:true});
const slow = fetch(base + "/slow", {signal:controller.signal}).catch(e => e);
await fetch(base + "/ready");
const sibling = fetch(base + "/fast");
controller.abort(reason); controller.abort("second");
assert(await slow === reason && controller.signal.reason === reason && events === 1, "abort reason/event");
assert(await (await sibling).text() === "ok", "sibling was cancelled");
let before = false;
try { await fetch("http://unreachable.invalid/", {signal:AbortSignal.abort(reason)}); } catch (e) { before = e === reason; }
assert(before, "pre-aborted request");
const aborted = new Request(base + "/fast", {signal:AbortSignal.abort(reason)});
assert(await (await fetch(aborted, {signal:null})).text() === "ok", "null signal did not detach input signal");
const timed = AbortSignal.timeout(1);
await new Promise(resolve => timed.addEventListener("abort", resolve));
assert(timed.reason.name === "TimeoutError", "timeout reason");
$done();
})().catch(e => $done({body:String(e)}));`, server.URL), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if result.Body != nil {
		t.Fatalf("fetch abort: %s", result.Body.Bytes())
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("abort left the network request running")
	}
}

func TestRuntimeFetchRedirectMethods(t *testing.T) {
	for _, method := range []struct {
		name, after301302, after303 string
	}{
		{"GET", "GET", "GET"},
		{"HEAD", "HEAD", "HEAD"},
		{"POST", "GET", "GET"},
		{"PUT", "PUT", "GET"},
		{"PATCH", "PATCH", "GET"},
		{"DELETE", "DELETE", "GET"},
		{"PROPFIND", "PROPFIND", "GET"},
	} {
		for _, statuses := range [][]int{{301}, {302}, {303}, {307}, {308}, {301, 307}, {302, 308}, {303, 307}, {302, 303, 308}} {
			t.Run(fmt.Sprintf("%s/%v", method.name, statuses), func(t *testing.T) {
				wantMethod := method.name
				for _, status := range statuses {
					switch status {
					case 301, 302:
						wantMethod = method.after301302
					case 303:
						wantMethod = method.after303
					}
				}
				body := "payload\x00中文"
				if method.name == "GET" || method.name == "HEAD" {
					body = ""
				}
				wantBody := body
				if wantMethod != method.name {
					wantBody = ""
				}
				var targets atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					step, err := strconv.Atoi(strings.TrimPrefix(req.URL.Path, "/"))
					if err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if step < len(statuses) {
						w.Header().Set("Location", fmt.Sprintf("/%d", step+1))
						w.WriteHeader(statuses[step])
						return
					}
					targets.Add(1)
					data, err := io.ReadAll(req.Body)
					if err != nil {
						t.Error(err)
					}
					if req.Method != wantMethod || string(data) != wantBody || req.ContentLength != int64(len(wantBody)) {
						t.Errorf("target received %s body=%q length=%d; want %s body=%q", req.Method, data, req.ContentLength, wantMethod, wantBody)
					}
					for name, value := range map[string]string{
						"Content-Type": "application/octet-stream", "Content-Encoding": "identity",
						"Content-Language": "en", "Content-Location": "/payload",
					} {
						if wantMethod != method.name {
							value = ""
						}
						if got := req.Header.Get(name); got != value {
							t.Errorf("target %s=%q, want %q", name, got, value)
						}
					}
				}))
				defer server.Close()
				r := testRuntime(t, RuntimeOptions{})
				result, err := r.Run(t.Context(), fmt.Sprintf(`fetch(%q + "/0", {
  method:%q, body:%q || undefined,
  headers:{"Content-Type":"application/octet-stream", "Content-Encoding":"identity", "Content-Language":"en", "Content-Location":"/payload"}
}).then(response => {
  if (!response.ok || !response.redirected || response.url !== %q + "/" + %d) throw Error("redirect metadata");
  $done();
}).catch(error => $done({body:String(error)}));`, server.URL, method.name, body, server.URL, len(statuses)), Invocation{})
				if err != nil {
					t.Fatal(err)
				}
				defer result.Close()
				if result.Body != nil || targets.Load() != 1 {
					t.Fatalf("redirect result=%q, target requests=%d", result.Body.Bytes(), targets.Load())
				}
			})
		}
	}
}

func TestRuntimeFetchRedirectClientPolicy(t *testing.T) {
	for _, checkErr := range []error{nil, http.ErrUseLastResponse, errors.New("redirect blocked")} {
		t.Run(fmt.Sprint(checkErr), func(t *testing.T) {
			var requests, checks atomic.Int32
			client := &http.Client{
				Transport: runtimeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					requests.Add(1)
					defer req.Body.Close()
					data, err := io.ReadAll(req.Body)
					if err != nil || req.Method != "PUT" || string(data) != "payload" {
						t.Errorf("request method=%s body=%q error=%v", req.Method, data, err)
					}
					status, header := 200, make(http.Header)
					if req.URL.Host == "origin.example" {
						status = 302
						header.Set("Location", "http://other.example/final")
					} else if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
						t.Error("sensitive headers forwarded to another host")
					}
					return &http.Response{StatusCode: status, Header: header, Body: http.NoBody, Request: req}, nil
				}),
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					checks.Add(1)
					if req.Method != "PUT" || req.ContentLength != 7 || req.GetBody == nil || len(via) != 1 {
						t.Errorf("redirect policy saw incorrect request: %s length=%d via=%d", req.Method, req.ContentLength, len(via))
					}
					return checkErr
				},
			}
			wantStatus, wantRequests := 200, int32(2)
			if checkErr != nil {
				wantStatus, wantRequests = 302, 1
			}
			wantError := checkErr != nil && !errors.Is(checkErr, http.ErrUseLastResponse)
			r := testRuntime(t, RuntimeOptions{})
			result, err := r.Run(t.Context(), fmt.Sprintf(`(async () => {
try {
  const response = await fetch("http://origin.example/start", {method:"PUT", body:"payload", headers:{Authorization:"secret", Cookie:"session=secret"}});
  if (%t || response.status !== %d) throw Error("unexpected redirect result");
} catch (error) {
  if (!%t || !(error instanceof TypeError)) throw error;
}
$done();
})().catch(error => $done({body:String(error)}));`, wantError, wantStatus, wantError), Invocation{HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			defer result.Close()
			if result.Body != nil || requests.Load() != wantRequests || checks.Load() != 1 {
				t.Fatalf("result=%q requests=%d checks=%d", result.Body.Bytes(), requests.Load(), checks.Load())
			}
		})
	}
}

func TestRuntimeFetchRepeatedCookieHeaders(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		cookies := req.Cookies()
		if len(cookies) != 2 || cookies[0].Name != "one" || cookies[0].Value != "1" || cookies[1].Name != "two" || cookies[1].Value != "2" {
			t.Errorf("received cookies=%v, header=%q", cookies, req.Header.Get("Cookie"))
		}
		w.Header().Set("X-Cookie", req.Header.Get("Cookie"))
	}))
	defer server.Close()
	r := testRuntime(t, RuntimeOptions{})
	result, err := r.Run(t.Context(), fmt.Sprintf(`(async () => {
function assert(ok, message) { if (!ok) throw Error(message); }
const headers = new Headers([["Cookie", "one=1"], ["cOoKiE", "two=2"], ["X-Test", "one"], ["X-Test", "two"], ["Set-Cookie", "one=1"], ["Set-Cookie", "two=2"]]);
assert(headers.get("COOKIE") === "one=1; two=2", "cookie get");
assert([...headers].find(([name]) => name === "cookie")[1] === "one=1; two=2", "cookie iteration");
assert(new Headers(headers).get("cookie") === "one=1; two=2", "cookie copy");
assert(headers.get("x-test") === "one, two", "ordinary header separator");
assert(headers.getSetCookie().join("|") === "one=1|two=2" && [...headers].filter(([name]) => name === "set-cookie").length === 2, "set-cookie separation");
headers.delete("Set-Cookie");
const response = await fetch(%q, {headers});
assert(response.headers.get("x-cookie") === "one=1; two=2", "wire cookie header");
$done();
})().catch(error => $done({body:String(error)}));`, server.URL), Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if result.Body != nil || requests.Load() != 1 {
		t.Fatalf("cookie result=%q, requests=%d", result.Body.Bytes(), requests.Load())
	}
}
