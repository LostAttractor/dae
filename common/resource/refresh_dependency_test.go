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

func TestFailedDependencyPreservesParentRefreshDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var store RefreshStore
		fixed := false
		calls := make(map[string]int)
		client := &http.Client{Transport: refreshTransport(func(r *http.Request) (*http.Response, error) {
			calls[r.URL.Path]++
			if fixed && r.URL.Path == "/script" {
				return nil, errors.New("script unavailable")
			}
			data := "old"
			if fixed && r.URL.Path == "/module" {
				data = "fixed"
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(data)), Request: r}, nil
		})}
		load := func() string {
			t.Helper()
			ctx, session := store.Begin(t.Context(), 10*time.Minute, true)
			value, _, err := (Cache{}).Load(ctx, client, LoadOptions{Key: "dependency-deadline", MaxBytes: 256}, func(read ReadFunc) (string, error) {
				module, err := read(Source{Location: "https://resource.test/module"}, ReadOptions{MaxBytes: 128})
				if err != nil {
					return "", err
				}
				if string(module.Data) == "fixed" {
					return "fixed", nil
				}
				_, err = read(Source{Location: "https://resource.test/script"}, ReadOptions{MaxBytes: 128, RefreshInterval: new(time.Minute)})
				return string(module.Data), err
			})
			if err != nil {
				t.Fatal(err)
			}
			session.Commit()
			return value
		}
		if got := load(); got != "old" {
			t.Fatal(got)
		}
		fixed = true
		var got string
		for range 12 {
			time.Sleep(time.Minute)
			got = load()
		}
		if got != "fixed" || calls["/module"] < 2 {
			t.Fatalf("after 12m with 10m module interval: value=%q calls=%v; dependency failure kept delaying the repaired module", got, calls)
		}
	})
}
