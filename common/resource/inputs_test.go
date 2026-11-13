// SPDX-License-Identifier: AGPL-3.0-only

package resource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func roundTripInputs(t *testing.T, inputs *Inputs) *Inputs {
	t.Helper()
	var encoded bytes.Buffer
	if err := inputs.Encode(&encoded); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeInputs(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var again bytes.Buffer
	if err := decoded.Encode(&again); err != nil || !bytes.Equal(encoded.Bytes(), again.Bytes()) {
		t.Fatalf("unstable encoding: %v", err)
	}
	return decoded
}

func TestInputsBytesFreezeAndFailureIdentity(t *testing.T) {
	ctx, inputs := WithInputRecording(t.Context())
	data := []byte("original")
	calls := 0
	live := func(context.Context) ([]byte, error) { calls++; return data, nil }
	got, err := ReadInput(ctx, "config", live)
	if err != nil || string(got) != "original" {
		t.Fatalf("record: %q %v", got, err)
	}
	data[0] = '!'
	got[1] = '!'
	got, err = ReadInput(ctx, "config", live)
	if err != nil || string(got) != "original" || calls != 1 {
		t.Fatalf("record reuse: %q %v calls=%d", got, err, calls)
	}
	causes := []error{os.ErrNotExist, os.ErrPermission, os.ErrExist, os.ErrInvalid, context.Canceled, context.DeadlineExceeded, errors.New("")}
	for _, cause := range causes {
		_, err := ReadInput(ctx, "error:"+cause.Error(), func(context.Context) ([]byte, error) { return nil, cause })
		if !errors.Is(err, cause) {
			t.Fatal(err)
		}
	}
	replay := WithInputReplay(t.Context(), roundTripInputs(t, inputs))
	unexpected := func(context.Context) ([]byte, error) { t.Fatal("replay called live loader"); return nil, nil }
	got, err = ReadInput(replay, "config", unexpected)
	if err != nil || string(got) != "original" {
		t.Fatalf("replay: %q %v", got, err)
	}
	for _, cause := range causes {
		_, err := ReadInput(replay, "error:"+cause.Error(), unexpected)
		if err == nil || errors.Is(err, ErrInputReplay) || cause.Error() != "" && !errors.Is(err, cause) {
			t.Fatalf("failure identity: cause=%v err=%v", cause, err)
		}
		if errors.Is(cause, os.ErrNotExist) && !os.IsNotExist(err) || errors.Is(cause, os.ErrPermission) && !os.IsPermission(err) {
			t.Fatalf("legacy filesystem predicate lost: %v", err)
		}
	}
	if _, err := ReadInput(replay, "missing", unexpected); !errors.Is(err, ErrInputReplay) {
		t.Fatalf("strict missing: %v", err)
	}
	if _, err := ReadInput(WithInputReplay(t.Context(), nil), "missing", unexpected); !errors.Is(err, ErrInputReplay) {
		t.Fatalf("nil replay became live: %v", err)
	}
	if _, err := ReadInput(t.Context(), "config", live); err != nil || calls != 2 {
		t.Fatal("recording leaked outside its context")
	}
}

func TestInputsGroupFallbackCapturesAcceptedLocalAndRedirect(t *testing.T) {
	local := filepath.Join(t.TempDir(), "local")
	writeLocal := func(value string) {
		t.Helper()
		if err := os.WriteFile(local, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeLocal("local-old")
	var revision atomic.Int32
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/root" {
			http.Redirect(w, r, "/redirected/root", http.StatusFound)
			return
		}
		if revision.Load() != 0 && r.URL.Path == "/dependency" {
			if err := os.WriteFile(local, []byte("local-fallback"), 0600); err != nil {
				t.Error(err)
			}
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if revision.Load() == 0 {
			io.WriteString(w, "old")
		} else {
			io.WriteString(w, "rejected-fresh")
		}
	}))
	defer server.Close()
	cache := Cache{Namespace: "modules", Dir: t.TempDir()}
	opts := LoadOptions{Key: "group-interpretation", MaxBytes: 128}
	load := func(read ReadFunc) (string, error) {
		var values []string
		for _, path := range []string{local, server.URL + "/root", server.URL + "/dependency"} {
			result, err := read(Source{Location: path}, ReadOptions{MaxBytes: 64})
			if err != nil {
				return "", err
			}
			values = append(values, string(result.Data)+"@"+result.Location)
		}
		return strings.Join(values, "|"), nil
	}
	if _, _, err := cache.Load(t.Context(), server.Client(), opts, load); err != nil {
		t.Fatal(err)
	}
	writeLocal("local-rejected")
	revision.Store(1)
	ctx, inputs := WithInputRecording(t.Context())
	accepted, status, err := cache.Load(ctx, server.Client(), opts, load)
	if err != nil || status.RefreshError == nil || !strings.Contains(accepted, "local-fallback@") || !strings.Contains(accepted, "old@"+server.URL+"/redirected/root") || strings.Contains(accepted, "rejected") {
		t.Fatalf("accepted fallback: %q %+v %v", accepted, status, err)
	}
	before := requests.Load()
	writeLocal("changed-after-recording")
	if err := os.RemoveAll(cache.Dir); err != nil {
		t.Fatal(err)
	}
	var store RefreshStore
	replay, session := store.Begin(WithInputReplay(t.Context(), roundTripInputs(t, inputs)), time.Hour, false)
	got, status, err := cache.Load(replay, server.Client(), opts, load)
	if err != nil || got != accepted || status.RefreshError == nil || requests.Load() != before || session.Fallbacks() != 1 {
		t.Fatalf("fallback replay: %q %+v %v requests=%d", got, status, err, requests.Load())
	}
	session.Commit()
	if len(store.groups[cache.Namespace+"\x00"+opts.Key].snapshot.Resources) != 2 || store.Next().IsZero() {
		t.Fatal("replay did not stage the accepted remote working set")
	}
	if _, err := os.Stat(cache.Dir); !os.IsNotExist(err) {
		t.Fatal("replay touched the cache directory")
	}
}

func TestInputsRefreshHitAndDirectRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, inputs := WithInputRecording(t.Context())
	source := Source{Location: path}
	options := ReadOptions{MaxBytes: 16}
	if _, err := Read(ctx, nil, source, options); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Read(WithInputReplay(t.Context(), roundTripInputs(t, inputs)), nil, source, options)
	if err != nil || string(got.Data) != "old" {
		t.Fatalf("direct read replay: %q %v", got.Data, err)
	}
	got, err = Read(t.Context(), nil, source, options)
	if err != nil || string(got.Data) != "new" {
		t.Fatal("direct read recording leaked into live context")
	}

	var store RefreshStore
	calls := 0
	client := &http.Client{Transport: refreshTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("cached")), Request: r}, nil
	})}
	cache := Cache{Namespace: "subscriptions"}
	opts := LoadOptions{Key: "subscription", MaxBytes: 128}
	load := func(read ReadFunc) (Result, error) {
		return read(Source{Location: "https://example.test/nodes"}, ReadOptions{MaxBytes: 128})
	}
	initial, session := store.Begin(t.Context(), time.Hour, false)
	if _, _, err := cache.Load(initial, client, opts, load); err != nil {
		t.Fatal(err)
	}
	session.Commit()
	record, recorded := WithInputRecording(t.Context())
	scheduled, _ := store.Begin(record, time.Hour, true)
	if _, _, err := cache.Load(scheduled, client, opts, load); err != nil || calls != 1 {
		t.Fatalf("scheduled reuse: %v calls=%d", err, calls)
	}
	result, _, err := cache.Load(WithInputReplay(t.Context(), roundTripInputs(t, recorded)), nil, opts, load)
	if err != nil || string(result.Data) != "cached" || calls != 1 {
		t.Fatalf("scheduled replay: %q %v", result.Data, err)
	}
}

func TestInputsGroupFailureAndStrictInterpretation(t *testing.T) {
	cache := Cache{Namespace: "one"}
	opts := LoadOptions{Key: "same", MaxBytes: 128}
	ctx, inputs := WithInputRecording(t.Context())
	failure := errors.New("subscription unavailable")
	if _, _, err := cache.Load(ctx, nil, opts, func(ReadFunc) (int, error) { return 0, failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	replay := WithInputReplay(t.Context(), roundTripInputs(t, inputs))
	unexpected := func(ReadFunc) (int, error) { t.Fatal("replayed failed group executed callback"); return 0, nil }
	if _, _, err := cache.Load(replay, nil, opts, unexpected); err == nil || errors.Is(err, ErrInputReplay) || err.Error() != failure.Error() {
		t.Fatalf("failed decision changed: %v", err)
	}
	for _, other := range []Cache{{Namespace: "two"}, {}} {
		if _, _, err := other.Load(replay, nil, opts, unexpected); !errors.Is(err, ErrInputReplay) {
			t.Fatalf("different namespace: %v", err)
		}
	}
	changed := opts
	changed.Key += ":new-interpretation"
	if _, _, err := cache.Load(replay, nil, changed, unexpected); !errors.Is(err, ErrInputReplay) {
		t.Fatalf("different interpretation key: %v", err)
	}

	path := filepath.Join(t.TempDir(), "group")
	if err := os.WriteFile(path, []byte("accepted"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, inputs = WithInputRecording(t.Context())
	load := func(read ReadFunc) (Result, error) {
		return read(Source{Location: path}, ReadOptions{MaxBytes: 128})
	}
	if _, _, err := cache.Load(ctx, nil, opts, load); err != nil {
		t.Fatal(err)
	}
	replay = WithInputReplay(t.Context(), roundTripInputs(t, inputs))
	for _, load := range []func(ReadFunc) (Result, error){
		func(read ReadFunc) (Result, error) { return read(Source{Location: path}, ReadOptions{MaxBytes: 64}) },
		func(read ReadFunc) (Result, error) {
			return read(Source{Location: path + "-missing"}, ReadOptions{MaxBytes: 128})
		},
		func(ReadFunc) (Result, error) { return Result{}, nil },
		func(read ReadFunc) (Result, error) {
			result, _ := load(read)
			return result, errors.New("new validation")
		},
		func(read ReadFunc) (Result, error) {
			_, _ = read(Source{Location: "missing"}, ReadOptions{MaxBytes: 128})
			return load(read)
		},
	} {
		if _, _, err := cache.Load(replay, nil, opts, load); !errors.Is(err, ErrInputReplay) {
			t.Fatalf("group divergence did not fail closed: %v", err)
		}
	}
}

func TestInputsParallelAndCancellation(t *testing.T) {
	ctx, inputs := WithInputRecording(t.Context())
	var calls atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			got, err := ReadInput(ctx, "shared", func(context.Context) ([]byte, error) {
				calls.Add(1)
				return []byte("immutable"), nil
			})
			if err != nil || string(got) != "immutable" {
				t.Errorf("parallel recording: %q %v", got, err)
			}
			if len(got) != 0 {
				got[0] = '!'
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("shared input called loader %d times", calls.Load())
	}
	replay := WithInputReplay(t.Context(), roundTripInputs(t, inputs))
	for range 16 {
		wg.Go(func() {
			got, err := ReadInput(replay, "shared", nil)
			if err != nil || string(got) != "immutable" {
				t.Errorf("parallel replay: %q %v", got, err)
			}
			if len(got) != 0 {
				got[0] = '!'
			}
		})
	}
	wg.Wait()
	canceled, cancel := context.WithCancel(replay)
	cancel()
	if _, err := ReadInput(canceled, "shared", nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(t.Context())
	record, pending := WithInputRecording(parent)
	entered, release := make(chan struct{}), make(chan struct{})
	wg.Go(func() {
		_, err := ReadInput(record, "pending", func(context.Context) ([]byte, error) {
			close(entered)
			<-release
			return nil, nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("loader cancellation: %v", err)
		}
	})
	<-entered
	if err := pending.Encode(io.Discard); !errors.Is(err, ErrInputRecording) {
		t.Fatalf("encoded pending input: %v", err)
	}
	cancel()
	if _, err := ReadInput(record, "pending", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter: %v", err)
	}
	close(release)
	wg.Wait()
	if err := pending.Encode(io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("encoded canceled operation: %v", err)
	}
}

func TestInputsLimitsAndPoisonedRecording(t *testing.T) {
	for _, setup := range []func(*Inputs){
		func(s *Inputs) { s.bytes = MaxInputArchiveBytes },
		func(s *Inputs) { s.indexBytes = maxInputIndex },
		func(s *Inputs) { s.reads = maxInputReads },
	} {
		ctx, inputs := WithInputRecording(t.Context())
		setup(inputs)
		if _, err := ReadInput(ctx, "key", func(context.Context) ([]byte, error) { return []byte("x"), nil }); !errors.Is(err, ErrInputRecording) {
			t.Fatalf("recording limit: %v", err)
		}
		if err := inputs.Encode(io.Discard); !errors.Is(err, ErrInputRecording) {
			t.Fatalf("partial recording encoded: %v", err)
		}
	}
	ctx, inputs := WithInputRecording(t.Context())
	if _, err := ReadInput(ctx, strings.Repeat("x", maxInputString+1), nil); !errors.Is(err, ErrInputRecording) {
		t.Fatal(err)
	}
	ctx, inputs = WithInputRecording(t.Context())
	for i := range maxInputKeys {
		if _, err := ReadInput(ctx, string(rune(i+1)), func(context.Context) ([]byte, error) { return nil, nil }); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ReadInput(ctx, "one-too-many", nil); !errors.Is(err, ErrInputRecording) {
		t.Fatal(err)
	}
	ctx, inputs = WithInputRecording(t.Context())
	path := filepath.Join(t.TempDir(), "local")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err := (Cache{}).Load(ctx, nil, LoadOptions{Key: "local-limit", MaxBytes: 128}, func(read ReadFunc) (Result, error) {
		for range maxGroupReads + 1 {
			_, _ = read(Source{Location: path}, ReadOptions{MaxBytes: 8})
		}
		return Result{}, nil // A caller cannot suppress a recording limit error.
	})
	if !errors.Is(err, ErrInputRecording) {
		t.Fatalf("group read count limit was swallowed: %v", err)
	}
	if err := inputs.Encode(io.Discard); !errors.Is(err, ErrInputRecording) {
		t.Fatalf("invalid local recording encoded: %v", err)
	}
}

func inputPacket(t *testing.T) []byte {
	t.Helper()
	ctx, inputs := WithInputRecording(t.Context())
	for _, key := range []string{"a", "b"} {
		if _, err := ReadInput(ctx, key, func(context.Context) ([]byte, error) { return []byte("payload"), nil }); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := inputs.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func resignInputPacket(packet []byte) {
	digest := sha256.Sum256(packet[:len(packet)-sha256.Size])
	copy(packet[len(packet)-sha256.Size:], digest[:])
}

func TestInputsCodecRejectsMalformedPackets(t *testing.T) {
	original := inputPacket(t)
	for n := range len(original) {
		if _, err := DecodeInputs(bytes.NewReader(original[:n])); !errors.Is(err, ErrInputReplay) {
			t.Fatalf("accepted truncated packet at %d: %v", n, err)
		}
	}
	for _, test := range []struct {
		name   string
		change func([]byte)
	}{
		{"version", func(p []byte) { p[7]++ }},
		{"key count", func(p []byte) { binary.LittleEndian.PutUint32(p[8:], maxInputKeys+1) }},
		{"read count", func(p []byte) { binary.LittleEndian.PutUint32(p[12:], maxInputReads+1) }},
		{"index limit", func(p []byte) { binary.LittleEndian.PutUint32(p[16:], maxInputIndex+1) }},
		{"total limit", func(p []byte) { binary.LittleEndian.PutUint64(p[20:], MaxInputArchiveBytes+1) }},
		{"overflow", func(p []byte) { binary.LittleEndian.PutUint64(p[20:], ^uint64(0)) }},
		{"key length", func(p []byte) { binary.LittleEndian.PutUint32(p[inputsHeaderSize+5:], maxInputString+1) }},
		{"duplicate key", func(p []byte) { p[inputsHeaderSize+88+9] = 'a' }},
		{"offset", func(p []byte) { binary.LittleEndian.PutUint64(p[inputsHeaderSize+72:], 1) }},
		{"item size", func(p []byte) { binary.LittleEndian.PutUint64(p[inputsHeaderSize+80:], MaxInputBytes+1) }},
		{"unknown error", func(p []byte) { p[inputsHeaderSize+18] = 255 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := bytes.Clone(original)
			test.change(packet)
			resignInputPacket(packet)
			if _, err := DecodeInputs(bytes.NewReader(packet)); !errors.Is(err, ErrInputReplay) {
				t.Fatalf("accepted malformed packet: %v", err)
			}
		})
	}
	corrupt := bytes.Clone(original)
	corrupt[len(corrupt)-sha256.Size-1] ^= 1
	if _, err := DecodeInputs(bytes.NewReader(corrupt)); !errors.Is(err, ErrInputReplay) {
		t.Fatalf("accepted payload corruption: %v", err)
	}
	if _, err := DecodeInputs(bytes.NewReader(append(bytes.Clone(original), 0))); !errors.Is(err, ErrInputReplay) {
		t.Fatalf("accepted trailing data: %v", err)
	}
	if _, err := DecodeInputs(errorInputReader{}); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrInputReplay) {
		t.Fatalf("decode cancellation: %v", err)
	}
}

type errorInputReader struct{}

func (errorInputReader) Read([]byte) (int, error) { return 0, context.Canceled }

type shortInputWriter struct{}

func (shortInputWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestInputsEncodeShortWrite(t *testing.T) {
	_, inputs := WithInputRecording(t.Context())
	if err := inputs.Encode(shortInputWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
}

func TestInputsNestedFatalCannotBecomeRecordedFailure(t *testing.T) {
	for _, fatal := range []error{ErrInputRecording, ErrInputReplay} {
		ctx, inputs := WithInputRecording(t.Context())
		live := func(context.Context) ([]byte, error) { return nil, fatal }
		if _, err := ReadInput(ctx, "nested", live); !errors.Is(err, fatal) {
			t.Fatalf("original fatal downgraded: %v", err)
		}
		if _, err := ReadInput(ctx, "nested", nil); !errors.Is(err, fatal) {
			t.Fatalf("reused fatal downgraded: %v", err)
		}
		if err := inputs.Encode(io.Discard); !errors.Is(err, fatal) {
			t.Fatalf("encoded fatal as ordinary skip: %v", err)
		}
	}
}

func TestInputsAcceptedGroupCanContainReadFailures(t *testing.T) {
	ctx, inputs := WithInputRecording(t.Context())
	path := filepath.Join(t.TempDir(), "local")
	if err := os.WriteFile(path, []byte("local is not in the remote limit"), 0600); err != nil {
		t.Fatal(err)
	}
	cache := Cache{Namespace: "optional-dependency"}
	opts := LoadOptions{Key: "group", MaxBytes: 1}
	reverse := false
	load := func(read ReadFunc) (Result, error) {
		optional := func() {
			// An optional malformed read must replay its ordinary error, not I/O.
			if _, err := read(Source{}, ReadOptions{}); err == nil || errors.Is(err, ErrInputReplay) {
				t.Fatalf("optional read failure: %v", err)
			}
		}
		if !reverse {
			optional()
		}
		result, err := read(Source{Location: path}, ReadOptions{MaxBytes: 128})
		if reverse {
			optional()
		}
		return result, err
	}
	accepted, _, err := cache.Load(ctx, nil, opts, load)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	reverse = true // Independent group reads need not repeat map iteration order.
	got, _, err := cache.Load(WithInputReplay(t.Context(), roundTripInputs(t, inputs)), nil, opts, load)
	if err != nil || !bytes.Equal(got.Data, accepted.Data) {
		t.Fatalf("accepted optional failure replay: %q %v", got.Data, err)
	}
}

func TestInputsBindingsDoNotSurviveRefreshSession(t *testing.T) {
	if HasInputs(t.Context()) || !HasInputs(WithInputReplay(t.Context(), nil)) {
		t.Fatal("binding must be explicit, including a failed replay binding")
	}
	ctx, inputs := WithInputRecording(t.Context())
	if !HasInputs(ctx) || HasInputs(withoutInputs(ctx)) {
		t.Fatal("incorrect explicit binding detection")
	}
	var store RefreshStore
	client := &http.Client{Transport: refreshTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("recorded")), Request: r}, nil
	})}
	cache := Cache{Namespace: "runtime"}
	opts := LoadOptions{Key: "live-after-replay", MaxBytes: 128}
	load := func(read ReadFunc) (Result, error) {
		return read(Source{Location: "https://example.test/runtime"}, ReadOptions{MaxBytes: 128})
	}
	if _, _, err := cache.Load(ctx, client, opts, load); err != nil {
		t.Fatal(err)
	}
	replay, session := store.Begin(WithInputReplay(t.Context(), roundTripInputs(t, inputs)), time.Hour, false)
	if _, _, err := cache.Load(replay, nil, opts, load); err != nil {
		t.Fatal(err)
	}
	session.Commit()
	live, _ := store.Begin(t.Context(), time.Hour, false)
	client.Transport = refreshTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("runtime-live")), Request: r}, nil
	})
	got, _, err := cache.Load(live, client, opts, load)
	if err != nil || string(got.Data) != "runtime-live" {
		t.Fatalf("runtime retained replay mode: %q %v", got.Data, err)
	}
}

type cancelInputWriter struct{ cancel context.CancelFunc }

func (w cancelInputWriter) Write(p []byte) (int, error) {
	w.cancel()
	return len(p), nil
}

func TestInputsEncodeCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	record, inputs := WithInputRecording(ctx)
	if _, err := ReadInput(record, "cancel-encoding", func(context.Context) ([]byte, error) { return []byte("bytes"), nil }); err != nil {
		t.Fatal(err)
	}
	if err := inputs.Encode(cancelInputWriter{cancel: cancel}); !errors.Is(err, context.Canceled) {
		t.Fatalf("encoding continued after cancellation: %v", err)
	}
}

func TestDerivedInputsShareOnlyImmutableOperationValues(t *testing.T) {
	record, inputs := WithInputRecording(t.Context())
	var builds, reads atomic.Int32
	build := func(ctx context.Context) (string, error) {
		builds.Add(1)
		data, err := ReadInput(ctx, "source", func(context.Context) ([]byte, error) {
			reads.Add(1)
			return []byte("frozen"), nil
		})
		return string(data), err
	}
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			if got, err := DeriveInput(record, "decoder:source", build); err != nil || got != "frozen" {
				t.Errorf("derived value = %q, %v", got, err)
			}
		})
	}
	workers.Wait()
	if builds.Load() != 1 || reads.Load() != 1 {
		t.Fatalf("parallel construction: builds=%d reads=%d", builds.Load(), reads.Load())
	}
	var before, after bytes.Buffer
	if err := inputs.Encode(&before); err != nil {
		t.Fatal(err)
	}
	// Result types isolate interpretations even when a namespace key is reused.
	if got, err := DeriveInput(record, "decoder:source", func(context.Context) (int, error) { return 7, nil }); err != nil || got != 7 {
		t.Fatalf("typed interpretation = %d, %v", got, err)
	}
	for range 2 {
		if got, err := DeriveInput(record, "nil", func(context.Context) (any, error) { return nil, nil }); err != nil || got != nil {
			t.Fatalf("nil interpretation = %v, %v", got, err)
		}
		if got, err := DeriveInput(record, "nil", func(context.Context) (*int, error) { return nil, nil }); err != nil || got != nil {
			t.Fatalf("nil pointer interpretation = %v, %v", got, err)
		}
	}
	for _, replay := range []context.Context{
		WithInputReplay(t.Context(), inputs),
		WithInputReplay(t.Context(), roundTripInputs(t, inputs)),
	} {
		if got, err := DeriveInput(replay, "decoder:source", build); err != nil || got != "frozen" {
			t.Fatalf("replay interpretation = %q, %v", got, err)
		}
	}
	if builds.Load() != 3 || reads.Load() != 1 {
		t.Fatalf("replay skipped its strict reader: builds=%d reads=%d", builds.Load(), reads.Load())
	}
	if err := inputs.Encode(&after); err != nil || !bytes.Equal(before.Bytes(), after.Bytes()) {
		t.Fatalf("derived values changed the input archive: %v", err)
	}
	for range 2 {
		if _, err := DeriveInput(t.Context(), "decoder:source", build); err != nil {
			t.Fatal(err)
		}
	}
	if reads.Load() != 3 {
		t.Fatal("ordinary contexts retained a derived value")
	}
	other, _ := WithInputRecording(t.Context())
	if _, err := DeriveInput(other, "decoder:source", build); err != nil || reads.Load() != 4 {
		t.Fatalf("independent operation reused a value: %v", err)
	}
}

func TestDerivedInputsCancellationAndFatalFailures(t *testing.T) {
	record, inputs := WithInputRecording(t.Context())
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		_, err := DeriveInput(record, "pending", func(context.Context) (string, error) {
			close(entered)
			<-release
			return "accepted", nil
		})
		if err != nil {
			t.Error(err)
		}
	}()
	<-entered
	waiting, cancel := context.WithTimeout(record, time.Millisecond)
	defer cancel()
	if _, err := DeriveInput(waiting, "pending", func(context.Context) (string, error) {
		t.Error("waiter invoked a second builder")
		return "", nil
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting ignored cancellation: %v", err)
	}
	if err := inputs.Encode(io.Discard); !errors.Is(err, ErrInputRecording) {
		t.Fatalf("encoded a pending interpretation: %v", err)
	}
	close(release)
	<-finished
	if got, err := DeriveInput(record, "pending", func(context.Context) (string, error) {
		t.Error("successful interpretation was rebuilt")
		return "", nil
	}); err != nil || got != "accepted" {
		t.Fatalf("waiter cancellation poisoned the builder: %q, %v", got, err)
	}
	canceled, stop := context.WithCancel(record)
	if _, err := DeriveInput(canceled, "canceled-build", func(context.Context) (int, error) {
		stop()
		return 1, nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("builder cancellation = %v", err)
	}
	if _, err := DeriveInput(record, "canceled-build", func(context.Context) (int, error) { return 2, nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled build became a successful cache hit: %v", err)
	}
	inputs.fail(errors.New("poisoned"))
	if _, err := DeriveInput(record, "pending", func(context.Context) (string, error) { return "", nil }); !errors.Is(err, ErrInputRecording) {
		t.Fatalf("cached value masked recording failure: %v", err)
	}
	for _, replay := range []context.Context{WithInputReplay(t.Context(), nil), WithInputReplay(t.Context(), inputs)} {
		if _, err := DeriveInput(replay, "pending", func(context.Context) (string, error) {
			t.Error("invalid replay invoked a builder")
			return "", nil
		}); !errors.Is(err, ErrInputReplay) {
			t.Fatalf("invalid replay lost fatal identity: %v", err)
		}
	}
	ctx, empty := WithInputRecording(t.Context())
	for i := range maxInputKeys {
		if _, err := DeriveInput(ctx, string(rune(i+1)), func(context.Context) (int, error) { return i, nil }); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := DeriveInput(ctx, "overflow", func(context.Context) (int, error) { return 0, nil }); !errors.Is(err, ErrInputRecording) {
		t.Fatalf("derived count limit = %v", err)
	}
	if err := empty.Encode(io.Discard); !errors.Is(err, ErrInputRecording) {
		t.Fatalf("derived limit did not invalidate recording: %v", err)
	}
}
