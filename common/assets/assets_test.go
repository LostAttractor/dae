package assets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/daeuniverse/dae/common/consts"
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
