package surge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"weak"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

type runtimeHarness struct {
	*Runtime
	t      *testing.T
	budget *membuffer.Budget
}

func (r *runtimeHarness) Run(ctx context.Context, source string, in Invocation) (*Result, error) {
	in.BodyMemory, in.BodyLimit = r.budget, 32<<20
	result, err := r.Runtime.Run(ctx, source, in)
	r.t.Cleanup(result.Close)
	return result, err
}
func testRuntime(t *testing.T, opts RuntimeOptions) *runtimeHarness {
	t.Helper()
	r, err := NewRuntime(opts)
	if err != nil {
		t.Fatal(err)
	}
	budget := membuffer.NewBudget(256 << 20)
	t.Cleanup(func() {
		if used := budget.Status().Used; used != 0 {
			t.Errorf("leaked body ownership: %d", used)
		}
	})
	return &runtimeHarness{Runtime: r, t: t, budget: budget}
}

func TestRuntimeConsoleLevels(t *testing.T) {
	var logs []string
	r := testRuntime(t, RuntimeOptions{Log: func(level, message string) {
		logs = append(logs, level+": "+message)
	}})
	_, err := r.Run(context.Background(), `
      console.log("message", {value: 1});
      console.info("info");
      console.warn("warning");
      console.error("error");
      console.debug("debug");
      $notification.post("title", "subtitle", "body");
      $done();
    `, Invocation{})
	if err != nil {
		t.Fatal(err)
	}
	want := "info: message {\"value\":1}\ninfo: info\nwarn: warning\nerror: error\ndebug: debug\ninfo: title subtitle body"
	if got := strings.Join(logs, "\n"); got != want {
		t.Fatalf("console output:\n%s\nwant:\n%s", got, want)
	}
}

func TestRuntimeRewrite(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	result, err := r.Run(context.Background(), `
      const body = JSON.parse($response.body);
      body.name = JSON.parse($argument).name;
      $done({body: JSON.stringify(body), headers: {...$response.headers, "X-Script": $script.name}});
    `, Invocation{ScriptName: "demo", ScriptType: "http-response", Argument: `{"name":"测试"}`,
		Request:  &Message{URL: "https://example.test/a"},
		Response: &Message{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: []byte(`{"name":"old"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Body == nil || string(result.Body.Bytes()) != `{"name":"测试"}` || result.Headers["X-Script"] != "demo" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestRuntimeBinaryAndText(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	result, err := r.Run(context.Background(), `
      if (!($response.body instanceof Uint8Array)) throw Error("not binary");
      let caught = false;
      try { new TextDecoder("utf-8", {fatal:true}).decode(new Uint8Array([255])); }
      catch (error) { caught = error instanceof Error && String(error).includes("invalid UTF-8"); }
      if (!caught) throw Error("host exception was not catchable");
      const encoded = new TextEncoder().encode("你好🌏");
      if (new TextDecoder().decode(encoded) !== "你好🌏") throw Error("text roundtrip");
      if (atob(btoa("\x00\xffabc")) !== "\x00\xffabc") throw Error("base64 roundtrip");
      const output = new Uint8Array($response.body.length + 1);
      output.set($response.body); output[output.length - 1] = 128;
      $done({body: output.subarray(1)});
    `, Invocation{BinaryBodyMode: true, Response: &Message{Body: []byte{0, 255, 254, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Body == nil || !bytes.Equal(result.Body.Bytes(), []byte{255, 254, 1, 128}) {
		t.Fatalf("binary body corrupt: %#v", result.Body)
	}
}

func TestRuntimeBase64Bridge(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	_, err := r.Run(context.Background(), `
      for (const [input, output] of [["", ""], ["Zg==", "f"], ["Zg", "f"],
          ["Zh==", "f"], ["Zm8", "fo"], [" Z\tm9v\n", "foo"]]) {
        if (atob(input) !== output) throw Error("base64 decoding: " + input);
      }
      for (const input of ["A", "===", "Zg=", "Zg==A", "Zg\u00a0", "-_=="]) {
        let rejected = false;
        try { atob(input); } catch (e) { rejected = e instanceof TypeError; }
        if (!rejected) throw Error("invalid base64 accepted: " + input);
      }
      // Cover all byte values, padding lengths and nonzero view offsets.
      for (let n = 0; n < 260; n++) {
        const raw = new Uint8Array(n + 2);
        for (let i = 0; i < raw.length; i++) raw[i] = i;
        const view = raw.subarray(1, n + 1);
        const text = String.fromCharCode(...view);
        if (atob(btoa(text)) !== text) throw Error("byte roundtrip: " + n);
      }
      // Script changes to public methods must not replace the host codec.
      Uint8Array.prototype.toBase64 = () => { throw Error("replaced encoder"); };
      Uint8Array.fromBase64 = () => { throw Error("replaced decoder"); };
      if (atob(btoa("\x00\xff")) !== "\x00\xff") throw Error("captured codecs");
      $done();
    `, Invocation{})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeMessageBodyEncoding(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	for _, body := range [][]byte{nil, {}, []byte("\xef\xbb\xbfhello\x00你好🚀"), {0xff, 0xfe, 'x'}} {
		for _, binaryMode := range []bool{false, true} {
			result, err := r.Run(context.Background(), `$done({body: $response.body});`, Invocation{
				BinaryBodyMode: binaryMode, Response: &Message{Body: body},
			})
			if err != nil {
				t.Fatal(err)
			}
			if body == nil {
				if result.Body != nil {
					t.Fatal("absent body became an empty body")
				}
				continue
			}
			want := body
			if !binaryMode {
				want = []byte(strings.TrimPrefix(strings.ToValidUTF8(string(body), "\ufffd"), "\ufeff"))
			}
			if result.Body == nil || !bytes.Equal(result.Body.Bytes(), want) {
				t.Fatalf("body=%v, binary=%v, want %v", result.Body, binaryMode, want)
			}
		}
	}
}

func TestRuntimeResultPresenceAndSyntheticResponse(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	for _, script := range []string{`$done()`, `$done({})`} {
		result, err := r.Run(context.Background(), script, Invocation{})
		if err != nil || result.Body != nil {
			t.Fatalf("omitted body: %v %#v", err, result)
		}
	}
	result, err := r.Run(context.Background(), `$done({response:{status:204,body:""}})`, Invocation{})
	if err != nil || result.Response == nil || result.Response.Status != 204 || result.Response.Body == nil || len(result.Response.Body.Bytes()) != 0 {
		t.Fatalf("synthetic response: %v %#v", err, result)
	}
	_, err = r.Run(context.Background(), `if ("body" in $request) throw Error("unexpected body"); $done()`, Invocation{Request: &Message{}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRuntimePromisesAndTimers(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	result, err := r.Run(context.Background(), `
      const cancelled = setTimeout(() => {throw Error("cancelled timer ran")}, 0);
      clearTimeout(cancelled);
      (async function () {
        await Promise.resolve();
        await new Promise(resolve => setTimeout(resolve, 5));
        $done({body:"async"});
      })();
    `, Invocation{})
	if err != nil || result.Body == nil || string(result.Body.Bytes()) != "async" {
		t.Fatalf("async result: %v %#v", err, result)
	}
}

func TestRuntimeHTTPCallbacks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Test", "ok")
		fmt.Fprintf(w, "%s:%s", r.Method, body)
	}))
	defer server.Close()
	r := testRuntime(t, RuntimeOptions{})
	result, err := r.Run(context.Background(), fmt.Sprintf(`
      $httpClient.post({url:%q,body:"hello"}, (error, response, data) => {
        if(error) throw Error(error);
        if(response.status !== 200 || response.headers["X-Test"] !== "ok") throw Error("response fields");
        Promise.resolve().then(() => $done({body:data}));
      });
    `, server.URL), Invocation{HTTPClient: server.Client()})
	if err != nil || result.Body == nil || string(result.Body.Bytes()) != "POST:hello" {
		t.Fatalf("HTTP result: %v %#v", err, result)
	}
	result, err = r.Run(context.Background(), fmt.Sprintf(`
      $httpClient.post({url:%q,body:new Uint8Array([0,255]),"binary-mode":true}, (error, response, data) => {
        if(error) throw Error(error);
        if(!(data instanceof Uint8Array)) throw Error("binary-mode returned text");
        $done({body:data.subarray(5)});
      });
    `, server.URL), Invocation{HTTPClient: server.Client()})
	if err != nil || result.Body == nil || !bytes.Equal(result.Body.Bytes(), []byte{0, 255}) {
		t.Fatalf("HTTP binary result: %v %#v", err, result)
	}
	result, err = r.Run(context.Background(), `$httpClient.get("file:///etc/passwd", error => $done({body: error}))`, Invocation{})
	if err != nil || result.Body == nil || !strings.Contains(string(result.Body.Bytes()), "only supports") {
		t.Fatalf("HTTP protocol restriction: %v %#v", err, result)
	}
}

// The downloaded upstream scripts are deliberately not vendored. Set this to a
// directory containing youtube.request.js and youtube.response.js to repeat the
// compatibility check against a chosen upstream version.
func TestRuntimeMaaseaCompatibility(t *testing.T) {
	dir := os.Getenv("DAE_SURGE_MAASEA_FIXTURES")
	if dir == "" {
		t.Skip("set DAE_SURGE_MAASEA_FIXTURES to a directory containing the upstream YouTube scripts")
	}
	requestSource, err := os.ReadFile(filepath.Join(dir, "youtube.request.js"))
	if err != nil {
		t.Fatal(err)
	}
	responseSource, err := os.ReadFile(filepath.Join(dir, "youtube.response.js"))
	if err != nil {
		t.Fatal(err)
	}
	var logs []string
	r := testRuntime(t, RuntimeOptions{Log: func(_ string, s string) { logs = append(logs, s) }})
	request := &Message{
		URL: "https://youtubei.googleapis.com/youtubei/v1/log_event", Method: "POST", Body: []byte{},
		Headers: map[string]string{"User-Agent": "com.google.ios.youtube/20.0", "Content-Encoding": "gzip", "X-Youtube-Hot-Hash-Data": "stale"},
	}
	result, err := r.Run(context.Background(), string(requestSource), Invocation{Request: request, BinaryBodyMode: true, ScriptType: "http-request"})
	if err != nil || result.Headers == nil || result.Headers["Content-Encoding"] != "" || result.Headers["X-Youtube-Hot-Hash-Data"] != "" {
		t.Fatalf("Maasea log_event header rewrite failed: %v %#v logs %v", err, result, logs)
	}
	request.URL = "https://rr1.googlevideo.com/initplayback?foo=bar&ack=1"
	result, err = r.Run(context.Background(), string(requestSource), Invocation{Request: request, BinaryBodyMode: true, ScriptType: "http-request", Argument: `{"captionLang":"off"}`})
	if err != nil || result.Response == nil || result.Response.Status != 200 || result.Response.Body == nil || len(result.Response.Body.Bytes()) != 0 {
		t.Fatalf("Maasea initplayback synthetic response failed: %v %#v logs %v", err, result, logs)
	}
	request.URL = "https://youtubei.googleapis.com/youtubei/v1/player"
	// Player.playabilityStatus field 2, adPlacements field 7, and adSlots
	// field 68. The latter two should be removed, while field 2 gains PiP
	// and background playback settings.
	result, err = r.Run(context.Background(), string(responseSource), Invocation{
		Request: request, Response: &Message{Status: 200, Body: []byte{0x12, 0, 0x3a, 0, 0xa2, 4, 0}},
		BinaryBodyMode: true, ScriptType: "http-response", Argument: `{"captionLang":"off","blockUpload":true,"blockImmersive":true,"blockShorts":false}`,
	})
	if err != nil || result.Body == nil || len(result.Body.Bytes()) <= 2 || (result.Body.Bytes())[0] != 0x12 || int((result.Body.Bytes())[1])+2 != len(result.Body.Bytes()) {
		t.Fatalf("Maasea binary player rewrite failed: %v %#v logs %v", err, result, logs)
	}
}

func TestRuntimeExecutionLimits(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{Timeout: 50 * time.Millisecond})
	for _, source := range []string{
		`while (true) {}`,
		`Promise.resolve().then(() => {while(true){}})`,
		`function spin(){Promise.resolve().then(spin)}; spin()`,
		`setTimeout(() => {while (true) {}}, 0)`,
		`setTimeout(() => $done(), 10000)`,
	} {
		t.Run(source, func(t *testing.T) {
			start := time.Now()
			_, err := r.Run(context.Background(), source, Invocation{})
			if err == nil || time.Since(start) > time.Second {
				t.Fatalf("execution budget failed: %v elapsed %v", err, time.Since(start))
			}
		})
	}
}

func TestRuntimeErrors(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	_, err := r.Run(context.Background(), `42`, Invocation{})
	if !errors.Is(err, ErrMissingDone) {
		t.Fatalf("missing done: %v", err)
	}
	_, err = r.Run(context.Background(), `throw Error("test failure")`, Invocation{})
	if err == nil || !strings.Contains(err.Error(), "test failure") {
		t.Fatalf("exception: %v", err)
	}
}

func TestRuntimePersistentStoreConcurrentReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	a := testRuntime(t, RuntimeOptions{StorePath: path})
	b := testRuntime(t, RuntimeOptions{StorePath: path})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := a
			if i%2 == 0 {
				r = b
			}
			_, err := r.Run(context.Background(), fmt.Sprintf(`
              if(!$persistentStore.write(%q,%q)) throw Error("store failed"); $done();
            `, fmt.Sprint(i), fmt.Sprint(i)), Invocation{})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	result, err := b.Run(context.Background(), `
      let sum = 0; for(let i = 0; i < 8; i++) sum += Number($persistentStore.read(String(i)));
      $done({body:String(sum)});
    `, Invocation{})
	if err != nil || result.Body == nil || string(result.Body.Bytes()) != "28" {
		t.Fatalf("concurrent store data lost: %v %#v", err, result)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("store permissions: %v %v", st, err)
	}
}

func TestRuntimeRetiredStoreIsReleased(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	previous := func() weak.Pointer[runtimeStore] {
		r := testRuntime(t, RuntimeOptions{StorePath: path})
		if !r.data.write("value", "initial", false) {
			t.Fatal("could not write store")
		}
		return weak.Make(r.data)
	}()
	for range 10 {
		goruntime.GC()
		if previous.Value() == nil {
			break
		}
	}
	if previous.Value() != nil {
		t.Fatal("retired runtime's store is retained by the global cache")
	}
	// With no live runtime sharing the path, a fresh instance reloads the file.
	if err := os.WriteFile(path, []byte(`{"value":"updated"}`), 0600); err != nil {
		t.Fatal(err)
	}
	next := testRuntime(t, RuntimeOptions{StorePath: path})
	if got := next.data.read("value"); got != "updated" {
		t.Fatalf("fresh runtime read stale data: %v", got)
	}
}
