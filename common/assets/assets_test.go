package assets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/resource"
)

func TestLocationFinderPriority(t *testing.T) {
	home, dirs := xdg.DataHome, xdg.DataDirs
	t.Cleanup(func() { xdg.DataHome, xdg.DataDirs = home, dirs })
	xdg.DataHome = t.TempDir()
	xdg.DataDirs = []string{t.TempDir(), t.TempDir()}
	extern := []string{t.TempDir(), t.TempDir()}
	location := t.TempDir()
	xdgPaths := []string{
		filepath.Join(xdg.DataHome, consts.AppName),
		filepath.Join(xdg.DataDirs[0], consts.AppName),
		filepath.Join(xdg.DataDirs[1], consts.AppName),
	}
	for _, path := range xdgPaths {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, env := range []bool{true, false} {
		t.Run(fmt.Sprintf("env=%t", env), func(t *testing.T) {
			filename := filepath.Base(filepath.Dir(t.TempDir())) + ".dat"
			for _, path := range append(append([]string{location}, extern...), xdgPaths...) {
				if err := os.WriteFile(filepath.Join(path, filename), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var priority, searchDirs []string
			if env {
				t.Setenv("DAE_LOCATION_ASSET", location)
				priority = append([]string{location}, extern...)
				searchDirs = append(append([]string{}, priority...), "/usr/local/share/"+consts.AppName, "/usr/share/"+consts.AppName)
			} else {
				t.Setenv("DAE_LOCATION_ASSET", "")
				priority = append(append([]string{}, extern...), xdgPaths...)
				searchDirs = priority
			}
			for _, path := range priority {
				want := filepath.Join(path, filename)
				got, err := NewLocationFinder(extern).GetLocationAsset(filename)
				if err != nil || got != want {
					t.Fatalf("location = %q, %v; want %q", got, err, want)
				}
				if err := os.Remove(want); err != nil {
					t.Fatal(err)
				}
			}
			_, err := NewLocationFinder(extern).GetLocationAsset(filename)
			want := fmt.Sprintf("%v: %v in [%v]", filename, os.ErrNotExist, strings.Join(searchDirs, ", "))
			if !errors.Is(err, os.ErrNotExist) || err.Error() != want {
				t.Fatalf("missing asset error = %v, want %q", err, want)
			}
		})
	}
}

func TestLocationFinderCache(t *testing.T) {
	location, extern := t.TempDir(), t.TempDir()
	t.Setenv("DAE_LOCATION_ASSET", location)
	const filename = "asset.dat"
	for _, path := range []string{location, extern} {
		if err := os.WriteFile(filepath.Join(path, filename), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	finder := NewLocationFinder([]string{extern})
	want := filepath.Join(location, filename)
	if got, err := finder.GetLocationAsset(filename); err != nil || got != want {
		t.Fatalf("initial location = %q, %v; want %q", got, err, want)
	}
	if err := os.Remove(want); err != nil {
		t.Fatal(err)
	}
	if got, err := finder.GetLocationAsset(filename); err != nil || got != want {
		t.Fatalf("cached location = %q, %v; want %q", got, err, want)
	}
	finder.mu.Lock()
	item := finder.m[filename]
	item.CacheDeadline = time.Now().Add(-time.Second)
	finder.m[filename] = item
	finder.mu.Unlock()
	want = filepath.Join(extern, filename)
	if got, err := finder.GetLocationAsset(filename); err != nil || got != want {
		t.Fatalf("location after expiry = %q, %v; want %q", got, err, want)
	}
}

func TestInputReplayFreezesAssetLocationAndBytes(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	t.Setenv("DAE_LOCATION_ASSET", first)
	const name = "frozen.dat"
	path := filepath.Join(first, name)
	if err := os.WriteFile(path, []byte("accepted"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, inputs := resource.WithInputRecording(t.Context())
	finder := NewLocationFinder([]string{second})
	selected, err := finder.GetLocationAssetContext(ctx, name)
	if err != nil || selected != path {
		t.Fatalf("recorded selection: %q, %v", selected, err)
	}
	if _, err := ReadFileContext(ctx, selected); err != nil {
		t.Fatal(err)
	}
	_, missingErr := finder.GetLocationAssetContext(ctx, "missing.dat")
	if !errors.Is(missingErr, os.ErrNotExist) {
		t.Fatal(missingErr)
	}
	var encoded bytes.Buffer
	if err := inputs.Encode(&encoded); err != nil {
		t.Fatal(err)
	}
	saved, err := resource.DecodeInputs(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(first); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{name, "missing.dat"} {
		if err := os.WriteFile(filepath.Join(second, file), []byte("changed"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DAE_LOCATION_ASSET", second)
	replay := resource.WithInputReplay(t.Context(), saved)
	fresh := NewLocationFinder([]string{second})
	if got, err := fresh.GetLocationAssetContext(replay, name); err != nil || got != path {
		t.Fatalf("replay rediscovered asset: %q, %v", got, err)
	}
	if data, err := ReadFileContext(replay, path); err != nil || string(data) != "accepted" {
		t.Fatalf("replay reread live asset: %q, %v", data, err)
	}
	if _, err := fresh.GetLocationAssetContext(replay, "missing.dat"); !errors.Is(err, os.ErrNotExist) || errors.Is(err, resource.ErrInputReplay) {
		t.Fatalf("recorded absence changed: %v", err)
	}
	if _, err := fresh.GetLocationAssetContext(replay, "uncaptured.dat"); !errors.Is(err, resource.ErrInputReplay) {
		t.Fatalf("missing lookup did not fail closed: %v", err)
	}
}

func TestAssetPathsPreserveNonUTF8Bytes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "parent-\xff")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	names := []string{"asset-\xff.dat", "asset-\xfe.dat"}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	record, inputs := resource.WithInputRecording(t.Context())
	check := func(ctx context.Context) {
		t.Helper()
		finder := NewLocationFinder([]string{dir})
		for _, name := range names {
			path, err := finder.GetLocationAssetContext(ctx, name)
			if err != nil || path != filepath.Join(dir, name) {
				t.Fatalf("raw asset selection: %q, %v", path, err)
			}
			data, err := ReadFileContext(ctx, path)
			if err != nil || string(data) != name {
				t.Fatalf("raw asset bytes: %q, %v", data, err)
			}
		}
	}
	check(t.Context())
	check(record)
	if _, err := NewLocationFinder(nil).GetLocationAssetContext(record, names[0]+"\x00"+dir); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("NUL path collided with a recorded tuple: %v", err)
	}
	var encoded bytes.Buffer
	if err := inputs.Encode(&encoded); err != nil {
		t.Fatal(err)
	}
	saved, err := resource.DecodeInputs(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	check(resource.WithInputReplay(t.Context(), saved))
}

type cancelAssetLookupContext struct {
	context.Context
	cancel context.CancelFunc
}

func (c *cancelAssetLookupContext) Err() error {
	err := c.Context.Err()
	c.cancel() // Model cancellation immediately after a successful initial check.
	return err
}

func TestLiveAssetLookupHonorsCancellationAfterInitialCheck(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "geo.dat"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx = &cancelAssetLookupContext{Context: ctx, cancel: cancel}
	if _, err := NewLocationFinder([]string{dir}).GetLocationAssetContext(ctx, "geo.dat"); !errors.Is(err, context.Canceled) {
		t.Fatalf("live lookup returned a result after cancellation: %v", err)
	}
}

func TestAssetCaptureLimitIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.dat")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, resource.MaxInputBytes+1); err != nil {
		t.Fatal(err)
	}
	ctx, inputs := resource.WithInputRecording(t.Context())
	for range 2 {
		if _, err := ReadFileContext(ctx, path); !errors.Is(err, resource.ErrInputRecording) {
			t.Fatalf("oversized asset failure became nonfatal: %v", err)
		}
	}
	if err := inputs.Encode(new(bytes.Buffer)); !errors.Is(err, resource.ErrInputRecording) {
		t.Fatalf("failed recording was encoded: %v", err)
	}
	if _, err := ReadFileContext(resource.WithInputReplay(t.Context(), nil), path); !errors.Is(err, resource.ErrInputReplay) {
		t.Fatalf("missing bytes read live asset: %v", err)
	}
}
