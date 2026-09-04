package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/outbound/protocol/direct"
)

func TestPersistentSubscriptionTagsRejectDuplicates(t *testing.T) {
	_, err := persistentSubscriptionTags([]config.Subscription{
		{Name: "shared", Link: "http-file://example.com/one"},
		{Name: "shared", Link: "https-file://example.com/two"},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate persistent subscription tag") {
		t.Fatalf("persistentSubscriptionTags error = %v, want duplicate tag error", err)
	}
}

func TestResolveNodeDescriptorsRunsSubscriptionsConcurrentlyInOrder(t *testing.T) {
	conf := &config.Config{Global: config.Global{DisableWaitingNetwork: true}}
	for i := range maxConcurrentSubscriptions + 2 {
		conf.Subscription = append(conf.Subscription, config.Subscription{Link: fmt.Sprintf("https://example.com/%d", i)})
	}

	started := make(chan string, len(conf.Subscription))
	release := make(chan struct{})
	var current atomic.Int32
	var maximum atomic.Int32
	resolve := func(_ context.Context, _ *http.Client, _, link string, _ func(string) error) (string, []string, error) {
		running := current.Add(1)
		defer current.Add(-1)
		for {
			observed := maximum.Load()
			if running <= observed || maximum.CompareAndSwap(observed, running) {
				break
			}
		}
		started <- link
		<-release
		return "tag-" + link, []string{"node-" + link}, nil
	}

	type result struct {
		descriptors []string
		err         error
	}
	subscriptionDir := t.TempDir()
	t.Setenv("DAE_LOCATION_SUBSCRIPTION", subscriptionDir)
	done := make(chan result, 1)
	go func() {
		descriptors, err := resolveNodeDescriptors(context.Background(), conf, nil, false, subscriptionDir, resolve)
		links := make([]string, 0, len(descriptors))
		for _, descriptor := range descriptors {
			links = append(links, descriptor.Link)
		}
		done <- result{descriptors: links, err: err}
	}()
	for range maxConcurrentSubscriptions {
		<-started
	}
	select {
	case link := <-started:
		t.Fatalf("subscription %q started above concurrency limit", link)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)

	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	want := make([]string, 0, len(conf.Subscription))
	for _, sub := range conf.Subscription {
		want = append(want, "node-"+sub.String())
	}
	if !reflect.DeepEqual(got.descriptors, want) {
		t.Fatalf("descriptor order = %v, want %v", got.descriptors, want)
	}
	if maximum.Load() != maxConcurrentSubscriptions {
		t.Fatalf("maximum concurrent resolutions = %d, want %d", maximum.Load(), maxConcurrentSubscriptions)
	}
}

func TestWaitForNetworkOnlineCanBeCanceled(t *testing.T) {
	requestStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		<-request.Context().Done()
	}))
	defer server.Close()

	previousLinks := CheckNetworkLinks
	previousDirect := direct.Direct
	CheckNetworkLinks = []string{server.URL}
	direct.InitDirectDialers("", false, 0)
	t.Cleanup(func() {
		CheckNetworkLinks = previousLinks
		direct.Direct = previousDirect
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- waitForNetworkOnline(ctx, false) }()
	<-requestStarted
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waitForNetworkOnline error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("network wait did not stop after cancellation")
	}
}
