// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuntimeMetadataAndEmptyArgument(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	r := testRuntime(t, RuntimeOptions{})
	seen := map[string]bool{}
	for _, configured := range []bool{false, true} {
		result, err := r.Run(t.Context(), fmt.Sprintf(`
          if ((typeof $argument !== "undefined") !== %t) throw Error("argument presence");
          if (%t && $argument !== "") throw Error("empty argument changed");
          if (Math.abs($script.startTime - Date.now()/1000) > 1) throw Error("startTime units");
          if ($environment.system !== "linux" || $environment.language !== "zh-CN" || !$environment["device-model"]) throw Error("environment");
          $done({body:$script.sessionID});`, configured, configured), Invocation{ArgumentSet: configured})
		if err != nil {
			t.Fatal(err)
		}
		id := string(result.Body.Bytes())
		if len(id) < 8 || seen[id] {
			t.Fatalf("invalid or reused session ID %q", id)
		}
		seen[id] = true
	}
}

func TestRuntimeStoreDefaultKeyUsesResolvedScriptPath(t *testing.T) {
	dir := t.TempDir()
	for name, data := range map[string]string{
		"one/module": "[Script]\na=type=dns,script-path=../shared.js\nb=type=dns,script-path=./other.js",
		"two/module": "[Script]\na=type=dns,script-path=../shared.js",
		"shared.js":  "$done();", "one/other.js": "$done();",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	one, err := Load(t.Context(), "file:one/module", nil, LoadOptions{BaseDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	two, err := Load(t.Context(), "file:two/module", nil, LoadOptions{BaseDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	r := testRuntime(t, RuntimeOptions{StorePath: filepath.Join(dir, "store.json")})
	for _, step := range []struct{ path, source string }{
		{one.Scripts[0].Path, `if (!$persistentStore.write("first")) throw Error("write"); $done();`},
		{one.Scripts[1].Path, `if ($persistentStore.read() !== null) throw Error("path collision"); $persistentStore.write("second"); $done();`},
		{two.Scripts[0].Path, `if ($persistentStore.read() !== "first") throw Error("same path not shared"); $persistentStore.write(null); if ($persistentStore.read() !== null) throw Error("delete"); $done();`},
	} {
		if _, err := r.Run(t.Context(), step.source, Invocation{ScriptPath: step.path}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = r.Run(t.Context(), `
      for (const value of [1, {}, undefined, true]) {
        let rejected = false; try { $persistentStore.write(value, "key"); } catch (e) { rejected = e instanceof TypeError; }
        if (!rejected) throw Error("non-string value accepted");
      }
      for (const key of ["", "a/b", "a\\b"]) {
        let rejected = false; try { $persistentStore.write("x", key); } catch (e) { rejected = e instanceof TypeError; }
        if (!rejected) throw Error("non-plain key accepted");
      }
      $done();`, Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	value := strings.Repeat("x", maxStoreValueSize)
	for _, key := range []string{"large-one", "large-two"} {
		if !r.data.write(t.Context(), key, value, false) {
			t.Fatal("per-value limit applied to whole store")
		}
	}
	if r.data.write(t.Context(), "too-large", value+"x", false) {
		t.Fatal("oversized value accepted")
	}
	stored, _, err := readRuntimeStoreSnapshot(r.data.path)
	if err != nil || stored["large-one"] != value || stored["large-two"] != value {
		t.Fatalf("large values lost: %v", err)
	}
}

func TestRuntimeUngzipFailureReturnsNull(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	if _, err := r.Run(t.Context(), `if ($utils.ungzip(new Uint8Array([1,2,3])) !== null) throw Error("ungzip failure"); $done();`, Invocation{}); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeHTTPOptionsAndSessionCookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/set":
			w.Header().Add("Set-Cookie", "session=one; Path=/; HttpOnly")
			w.Header().Add("Set-Cookie", "other=two; Path=/; Expires=Wed, 21 Oct 2037 07:28:00 GMT")
			w.Header().Set("Location", "/echo")
			w.WriteHeader(http.StatusFound)
		case "/echo":
			io.WriteString(w, req.Header.Get("Cookie"))
		case "/json":
			body, _ := io.ReadAll(req.Body)
			if req.Header.Get("Content-Type") != "application/json" || string(body) != `{"value":"中文"}` {
				t.Errorf("object body: %s %s", req.Header.Get("Content-Type"), body)
			}
			w.Write(body)
		}
	}))
	defer server.Close()
	r := testRuntime(t, RuntimeOptions{})
	source := fmt.Sprintf(`
      const base = %q;
      for (const insecure of [true, "false"]) {
        let rejected = false;
        try { $httpClient.get({url:base, insecure}, () => {}); } catch (e) { rejected = e instanceof TypeError; }
        if (!rejected) throw Error("unsupported insecure option accepted");
      }
      function get(path, options = {}) { return new Promise((resolve, reject) => $httpClient.get({url:base+path, ...options}, (e,r,d) => e ? reject(Error(e)) : resolve({r,d}))); }
      (async () => {
        if ((await get("/echo", {insecure:false})).d !== "") throw Error("cookies leaked across invocations");
        let x = await get("/set", {"auto-redirect":false,"auto-cookie":false,"full-header-mode":true});
        if (x.r.status !== 302 || !Array.isArray(x.r.headers)) throw Error("redirect/header options");
        const cookies = x.r.headers.filter(h => h.field.toLowerCase() === "set-cookie");
        if (cookies.length !== 2 || !cookies[1].value.includes("Wed, 21 Oct")) throw Error("duplicate cookies lost");
        if ((await get("/echo")).d !== "") throw Error("disabled cookie mode stored cookies");
        x = await get("/set");
        if (x.r.status !== 200 || !x.d.includes("session=one") || !x.d.includes("other=two")) throw Error("redirect cookies missing");
        if ((await get("/echo", {"auto-cookie":false,headers:{Cookie:"manual=yes"}})).d !== "manual=yes") throw Error("manual cookie changed");
        await new Promise((resolve,reject) => $httpClient.post({url:base+"/json",body:{value:"中文"}}, (e,r,d) => e ? reject(Error(e)) : resolve(d)));
        $done({headers:cookies});
      })();`, server.URL)
	for range 2 {
		result, err := r.Run(t.Context(), source, Invocation{HTTPClient: server.Client()})
		if err != nil || result == nil || len(result.Headers.Values("Set-Cookie")) != 2 {
			t.Fatalf("HTTP options: %+v %v", result, err)
		}
	}
	if server.Client().Jar != nil || server.Client().CheckRedirect != nil {
		t.Fatal("caller client modified")
	}
}

func TestRuntimeHTTPDefaultTimeout(t *testing.T) {
	runtimeFakeClockTest(t, func(t *testing.T) {
		client := &http.Client{Transport: runtimeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		})}
		r := testRuntime(t, RuntimeOptions{Timeout: 10 * time.Second})
		started := time.Now()
		_, err := r.Run(t.Context(), `$httpClient.get("https://example.test", e => { if (!e) throw Error("missing timeout"); $done(); });`, Invocation{HTTPClient: client})
		if err != nil || time.Since(started) != 5*time.Second {
			t.Fatalf("default HTTP deadline: %v elapsed=%s", err, time.Since(started))
		}
	})
}

func TestRuntimeHTTPRequestLimits(t *testing.T) {
	var calls atomic.Int32
	gate := make(chan struct{})
	client := &http.Client{Transport: runtimeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 20 {
			close(gate)
		}
		<-gate
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody}, nil
	})}
	r := testRuntime(t, RuntimeOptions{})
	_, err := r.Run(t.Context(), `
      let done = 0;
      for (let i=0; i<20; i++) $httpClient.get("https://example.test", e => { if(e) throw Error(e); if(++done===20) $done(); });
      let rejected = false; try { $httpClient.get("https://example.test", () => {}); } catch(e) { rejected = true; }
      if (!rejected) throw Error("21 concurrent requests accepted");`, Invocation{HTTPClient: client})
	if err != nil || calls.Load() != 20 {
		t.Fatalf("HTTP concurrency: %v calls=%d", err, calls.Load())
	}
	_, err = r.Run(t.Context(), `
      let count=0;
      function next() { $httpClient.get("https://example.test", e => { if(e) throw Error(e); if(++count===70) $done(); else next(); }); }
      next();`, Invocation{HTTPClient: client})
	if err != nil || calls.Load() != 90 {
		t.Fatalf("sequential HTTP limit: %v calls=%d", err, calls.Load())
	}
}

func TestRuntimeFullHeaderRoundTrip(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	header := http.Header{"Set-Cookie": {"a=1", "b=2"}, "X-Test": {"first", "second"}}
	result, err := r.Run(t.Context(), `
      if (!Array.isArray($response.headers)) throw Error("not full headers");
      $done({headers:$response.headers});`, Invocation{FullHeaderMode: true, Response: &Message{Headers: header}})
	if err != nil || !reflect.DeepEqual(result.Headers, header) {
		t.Fatalf("header round trip: %+v %v", result, err)
	}
}
