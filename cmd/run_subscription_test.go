package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/subscription"
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
	t.Setenv("DAE_LOCATION_CACHE", subscriptionDir)
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
	previousDirect, previousBootstrap := direct.Direct, direct.Bootstrap
	CheckNetworkLinks = []string{server.URL}
	direct.InitDirectDialers(false, 0)
	t.Cleanup(func() {
		CheckNetworkLinks = previousLinks
		direct.Direct = previousDirect
		direct.Bootstrap = previousBootstrap
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

func TestSubscriptionSourceDirectory(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "config")
	for _, test := range []struct {
		name, cache, source, want string
	}{
		{"default cache", "", "https://example.com/nodes", "/var/lib/dae"},
		{"default persistent cache", "", "tag:https-file://example.com/nodes", "/var/lib/dae"},
		{"configured cache", "/custom/cache", "tag:http-file://example.com/nodes", "/custom/cache"},
		{"ordinary local file", "", "file:nodes.sub", configDir},
		{"tagged local file with cache", "/custom/cache", "tag:file:nodes.sub", configDir},
		{"absolute local file", "/custom/cache", "file:///run/secrets/nodes.sub", configDir},
		{"tagged absolute local file", "/custom/cache", "tag:file:/run/secrets/nodes.sub", configDir},
		{"file tag with remote source", "/custom/cache", (config.Subscription{Name: "file", Link: "https-file://example.com/nodes"}).String(), "/custom/cache"},
		{"http tag with local source", "/custom/cache", (config.Subscription{Name: "http", Link: "file:nodes.sub"}).String(), configDir},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("DAE_LOCATION_CACHE", test.cache)
			if got := subscriptionSourceDirectory(test.source, configDir); got != test.want {
				t.Fatalf("subscriptionSourceDirectory = %q, want %q", got, test.want)
			}
		})
	}
}

func TestResolveNodeDescriptorsDoesNotCreateDirectoriesWithoutPersistentDownload(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "missing-config")
	cacheDir := filepath.Join(root, "missing-cache")
	t.Setenv("DAE_LOCATION_CACHE", cacheDir)
	conf := &config.Config{Global: config.Global{DisableWaitingNetwork: true}}
	if _, err := resolveNodeDescriptors(context.Background(), conf, nil, false, configDir, nil); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{configDir, cacheDir} {
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("directory %q was created without a persistent download: %v", dir, err)
		}
	}
}

func subscriptionTestContent(host string) (string, []byte) {
	credentials := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:test-password"))
	node := "ss://" + credentials + "@" + host + ":443"
	return node, []byte(base64.StdEncoding.EncodeToString([]byte(node + "\n")))
}

func TestResolveNodeDescriptorsLocalFileUsesConfigurationDirectory(t *testing.T) {
	configDir, cacheDir := t.TempDir(), t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", cacheDir)
	previousDirect, previousBootstrap := direct.Direct, direct.Bootstrap
	direct.InitDirectDialers(false, 0)
	t.Cleanup(func() { direct.Direct, direct.Bootstrap = previousDirect, previousBootstrap })
	node, content := subscriptionTestContent("configured.example")
	_, otherContent := subscriptionTestContent("cached.example")
	for dir, data := range map[string][]byte{configDir: content, cacheDir: otherContent} {
		if err := os.WriteFile(filepath.Join(dir, "nodes.sub"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	conf := &config.Config{
		Global:       config.Global{DisableWaitingNetwork: true},
		Subscription: []config.Subscription{{Name: "local", Link: "file:nodes.sub"}},
	}
	descriptors, err := resolveNodeDescriptors(context.Background(), conf, nil, false, configDir, subscription.ResolveSubscriptionContext)
	if err != nil {
		t.Fatal(err)
	}
	if len(descriptors) != 1 || descriptors[0].Link != node || descriptors[0].SubscriptionTag != "local" {
		t.Fatalf("local subscription descriptors = %+v, want configuration node %q", descriptors, node)
	}
}

func TestResolveNodeDescriptorsAbsoluteSecretSymlink(t *testing.T) {
	root := t.TempDir()
	configDir, cacheDir := filepath.Join(root, "missing-config"), filepath.Join(root, "missing-cache")
	t.Setenv("DAE_LOCATION_CACHE", cacheDir)
	previousDirect, previousBootstrap := direct.Direct, direct.Bootstrap
	direct.InitDirectDialers(false, 0)
	t.Cleanup(func() { direct.Direct, direct.Bootstrap = previousDirect, previousBootstrap })
	secretDir := filepath.Join(root, "run", "secrets.d", "1", "dae", "subscription")
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		t.Fatal(err)
	}
	node, content := subscriptionTestContent("flowercloud.example")
	if err := os.WriteFile(filepath.Join(secretDir, "flowercloud"), content, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("secrets.d/1", filepath.Join(root, "run", "secrets")); err != nil {
		t.Fatal(err)
	}
	source := (&url.URL{Scheme: "file", Path: filepath.Join(root, "run", "secrets", "dae", "subscription", "flowercloud")}).String()
	conf := &config.Config{
		Global:       config.Global{DisableWaitingNetwork: true},
		Subscription: []config.Subscription{{Name: "flowercloud", Link: source}},
	}
	descriptors, err := resolveNodeDescriptors(context.Background(), conf, nil, false, configDir, subscription.ResolveSubscriptionContext)
	if err != nil || len(descriptors) != 1 || descriptors[0].SubscriptionTag != "flowercloud" || descriptors[0].Link != node {
		t.Fatalf("secret subscription was not included in the node pool: descriptors=%+v err=%v", descriptors, err)
	}
	for _, dir := range []string{configDir, cacheDir} {
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("reading the absolute secret created %s: %v", dir, err)
		}
	}
}

func TestResolveNodeDescriptorsPersistsAndFallsBackInCacheDirectory(t *testing.T) {
	root := t.TempDir()
	configDir, cacheDir := filepath.Join(root, "missing-config"), filepath.Join(root, "cache")
	t.Setenv("DAE_LOCATION_CACHE", cacheDir)
	node, content := subscriptionTestContent("cached.example")
	var timedOut atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if timedOut.Load() {
			_, _ = w.Write([]byte(`{"message":"subscription request timed out"}`))
			return
		}
		_, _ = w.Write(content)
	}))
	defer server.Close()
	previousDirect, previousBootstrap := direct.Direct, direct.Bootstrap
	direct.InitDirectDialers(false, 0)
	t.Cleanup(func() { direct.Direct, direct.Bootstrap = previousDirect, previousBootstrap })
	conf := &config.Config{
		Global: config.Global{DisableWaitingNetwork: true},
		Subscription: []config.Subscription{{
			Name: "cached", Link: strings.Replace(server.URL, "http://", "http-file://", 1),
		}},
	}
	activeTags := map[string]struct{}{"cached": {}}
	for _, state := range []string{"fresh", "timeout response", "offline"} {
		timedOut.Store(state == "timeout response")
		if state == "offline" {
			server.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		descriptors, err := resolveNodeDescriptors(ctx, conf, activeTags, false, configDir, subscription.ResolveSubscriptionContext)
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", state, err)
		}
		if len(descriptors) != 1 || descriptors[0].Link != node || descriptors[0].SubscriptionTag != "cached" {
			t.Fatalf("%s: descriptors = %+v, want cached node %q", state, descriptors, node)
		}
	}
	cacheFile := filepath.Join(cacheDir, "persist.d", "cached.sub")
	got, err := os.ReadFile(cacheFile)
	if err != nil || string(got) != string(content) {
		t.Fatalf("cache %q = %q, %v; want downloaded content", cacheFile, got, err)
	}
	if _, err := os.Stat(configDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("persistent subscription created missing configuration directory: %v", err)
	}
}

func TestResolveNodeDescriptorsPrunesOnlyCacheDirectory(t *testing.T) {
	configDir, cacheDir := t.TempDir(), t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", cacheDir)
	for _, dir := range []string{configDir, cacheDir} {
		persistDir := filepath.Join(dir, "persist.d")
		if err := os.Mkdir(persistDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(persistDir, "stale.sub"), []byte("stale"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	conf := &config.Config{Global: config.Global{DisableWaitingNetwork: true}}
	if _, err := resolveNodeDescriptors(context.Background(), conf, nil, false, configDir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "persist.d", "stale.sub")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale cache subscription was not removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "persist.d", "stale.sub")); err != nil {
		t.Fatalf("prune touched the configuration directory: %v", err)
	}
}

func TestWaitForNetworkOnlineTimeoutAllowsOfflinePreparation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()
	previousLinks, previousDirect, previousBootstrap := CheckNetworkLinks, direct.Direct, direct.Bootstrap
	CheckNetworkLinks = []string{server.URL}
	direct.InitDirectDialers(false, 0)
	t.Cleanup(func() {
		CheckNetworkLinks = previousLinks
		direct.Direct = previousDirect
		direct.Bootstrap = previousBootstrap
	})
	started := time.Now()
	if err := waitForNetworkOnlineWithTimeout(context.Background(), 20*time.Millisecond); err != nil {
		t.Fatalf("offline network check prevented preparation: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("network check ignored its timeout: %v", elapsed)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := waitForNetworkOnlineWithTimeout(ctx, time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("parent deadline error = %v, want context deadline exceeded", err)
	}
}
