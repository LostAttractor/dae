// SPDX-License-Identifier: AGPL-3.0-only

package resource

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type refreshTransport func(*http.Request) (*http.Response, error)

func (f refreshTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRefreshRetriesUnavailableInitialResource(t *testing.T) {
	var store RefreshStore
	client := &http.Client{Transport: refreshTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })}
	for _, automatic := range []bool{false, true} {
		ctx, session := store.Begin(t.Context(), time.Hour, automatic)
		_, _, err := (Cache{}).Load(ctx, client, LoadOptions{Key: "subscription", MaxBytes: 128}, func(read ReadFunc) (Result, error) {
			return read(Source{Location: "https://example.test/nodes"}, ReadOptions{MaxBytes: 128})
		})
		if err == nil {
			t.Fatal("offline resource accepted")
		}
		session.Commit()
		if next := time.Until(store.Next()); next <= 0 || next > 5*time.Minute {
			t.Fatalf("missing retry: %v", next)
		}
	}
}

func TestRefreshIntervalChanges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var store RefreshStore
		reads := 0
		client := &http.Client{Transport: refreshTransport(func(r *http.Request) (*http.Response, error) {
			reads++
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("current")), Request: r}, nil
		})}
		load := func(interval *time.Duration) {
			t.Helper()
			ctx, session := store.Begin(t.Context(), time.Hour, true)
			_, _, err := (Cache{}).Load(ctx, client, LoadOptions{Key: "script", MaxBytes: 128}, func(read ReadFunc) (Result, error) {
				return read(Source{Location: "https://example.test/script"}, ReadOptions{MaxBytes: 128, RefreshInterval: interval})
			})
			if err != nil {
				t.Fatal(err)
			}
			session.Commit()
		}
		load(nil)
		load(nil)
		if reads != 1 || !store.Next().Equal(time.Now().Add(time.Hour)) {
			t.Fatalf("unchanged default: reads=%d next=%v", reads, store.Next())
		}
		load(new(time.Minute))
		if reads != 2 || !store.Next().Equal(time.Now().Add(time.Minute)) {
			t.Fatalf("changed interval: reads=%d next=%v", reads, store.Next())
		}
		load(new(time.Duration(0)))
		load(new(time.Duration(0)))
		if reads != 3 || !store.Next().IsZero() {
			t.Fatalf("disabled checks: reads=%d next=%v", reads, store.Next())
		}
		load(nil)
		if reads != 4 || !store.Next().Equal(time.Now().Add(time.Hour)) {
			t.Fatalf("restored default: reads=%d next=%v", reads, store.Next())
		}
	})
}

func TestRefreshIntervalsPublicationAndFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var store RefreshStore
		counts := make(map[string]int)
		revision, fail := "old", ""
		client := &http.Client{Transport: refreshTransport(func(r *http.Request) (*http.Response, error) {
			counts[r.URL.Path]++
			if r.URL.Path == fail {
				return nil, errors.New("unavailable")
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(revision)), Request: r}, nil
		})}
		cache := Cache{}
		load := func(automatic, commit bool) (string, CacheStatus) {
			t.Helper()
			ctx, session := store.Begin(t.Context(), time.Hour, automatic)
			value, status, err := cache.Load(ctx, client, LoadOptions{Key: "module", MaxBytes: 128}, func(read ReadFunc) (string, error) {
				var value string
				for _, item := range []struct {
					path     string
					interval *time.Duration
				}{{"/module", nil}, {"/script", new(time.Minute)}, {"/manual", new(time.Duration(0))}} {
					result, err := read(Source{Location: "https://resources.test" + item.path}, ReadOptions{MaxBytes: 128, RefreshInterval: item.interval})
					if err != nil {
						return "", err
					}
					value += string(result.Data) + "/"
				}
				return value, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if commit {
				session.Commit()
			}
			return value, status
		}
		if value, _ := load(false, true); value != "old/old/old/" {
			t.Fatal(value)
		}
		if next := store.Next(); !next.Equal(time.Now().Add(time.Minute)) {
			t.Fatalf("next=%v", next)
		}
		revision = "new"
		if value, _ := load(true, true); value != "old/old/old/" {
			t.Fatal(value)
		}
		time.Sleep(time.Minute)
		if value, _ := load(true, true); value != "old/new/old/" {
			t.Fatal(value)
		}
		if counts["/module"] != 1 || counts["/script"] != 2 || counts["/manual"] != 1 {
			t.Fatal(counts)
		}
		// A rejected configuration must not replace the active working set.
		load(false, false)
		if value, _ := load(true, true); value != "old/new/old/" {
			t.Fatal(value)
		}
		if value, _ := load(false, true); value != "new/new/new/" {
			t.Fatal(value)
		}
		revision, fail = "partial", "/manual"
		if value, status := load(false, true); value != "new/new/new/" || status.RefreshError == nil {
			t.Fatalf("mixed revisions on failure: %s %+v", value, status)
		}
		if !store.Next().After(time.Now()) {
			t.Fatal("failed refresh immediately rescheduled")
		}
		// A commit without the old group removes both its data and its timer.
		_, empty := store.Begin(t.Context(), time.Hour, true)
		empty.Commit()
		if !store.Next().IsZero() || len(store.groups) != 0 {
			t.Fatal("removed resources retained")
		}
	})
}
