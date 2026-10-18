// SPDX-License-Identifier: AGPL-3.0-only

package routing

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"google.golang.org/protobuf/proto"
)

func writeDatFixture(t testing.TB, path string, msg proto.Message) {
	t.Helper()
	data, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDatParamsCacheRefreshIsolationAndAttributes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geosite.dat")
	site := &geodata.GeoSite{CountryCode: "test", Domain: []*geodata.Domain{
		{Type: geodata.Domain_Full, Value: "old.test", Attribute: []*geodata.Domain_Attribute{{Key: "ads"}}},
		{Type: geodata.Domain_RootDomain, Value: "other.test"},
	}}
	writeDatFixture(t, path, &geodata.GeoSiteList{Entry: []*geodata.GeoSite{site}})
	reader := NewDatReaderOptimizer(t.Context(), assets.NewLocationFinder([]string{dir}))
	first, err := reader.loadGeoSite("geosite", "test@ads")
	if err != nil || len(first) != 1 || first[0].Val != "old.test" {
		t.Fatalf("first = %v, %v", first, err)
	}
	first[0].Val = "mutated.test"
	first[0].Annotation = []*config_parser.Param{{Val: "annotation"}}
	again, err := reader.loadGeoSite("geosite", "test@ads")
	if err != nil || len(again) != 1 || again[0].Val != "old.test" || len(again[0].Annotation) != 0 {
		t.Fatalf("cached mutable params: %v, %v", again, err)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			next := NewDatReaderOptimizer(t.Context(), assets.NewLocationFinder([]string{dir}))
			again, err := next.loadGeoSite("geosite", "test@ads")
			if err != nil || len(again) != 1 || again[0].Val != "old.test" || len(again[0].Annotation) != 0 {
				t.Errorf("shared mutable params: %v, %v", again, err)
			}
		})
	}
	workers.Wait()
	all, err := reader.loadGeoSite("geosite", "TEST")
	if err != nil || len(all) != 2 {
		t.Fatalf("attribute polluted complete set: %v, %v", all, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	site.Domain[0].Value = "new.test"
	writeDatFixture(t, path, &geodata.GeoSiteList{Entry: []*geodata.GeoSite{site}})
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	fresh, err := reader.loadGeoSite("geosite", "test@ads")
	if err != nil || len(fresh) != 1 || fresh[0].Val != "new.test" {
		t.Fatalf("stale expansion: %v, %v", fresh, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	reader.ctx = ctx
	if _, err := reader.loadGeoSite("geosite", "test@ads"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cache ignored cancellation: %v", err)
	}
}

func TestDatParamsCacheGeoIPAndInvalidEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geoip.dat")
	entry := &geodata.GeoIP{CountryCode: "test", Cidr: []*geodata.CIDR{{Ip: []byte{192, 0, 2, 0}, Prefix: 24}}}
	reader := NewDatReaderOptimizer(t.Context(), assets.NewLocationFinder([]string{dir}))
	writeDatFixture(t, path, &geodata.GeoIPList{Entry: []*geodata.GeoIP{entry}})
	for range 2 {
		params, err := reader.loadGeoIp("geoip", "test")
		if err != nil || len(params) != 1 || params[0].Val != "192.0.2.0/24" {
			t.Fatalf("params = %v, %v", params, err)
		}
		params[0].Val = "mutated"
	}
	entry.Cidr[0].Ip = []byte{1, 2}
	writeDatFixture(t, path, &geodata.GeoIPList{Entry: []*geodata.GeoIP{entry}})
	if _, err := reader.loadGeoIp("geoip", "test"); err == nil {
		t.Fatal("invalid replacement reused cache")
	}
}

func TestDatParamsCachePreparationLifetime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geosite.dat")
	writeDatFixture(t, path, &geodata.GeoSiteList{Entry: []*geodata.GeoSite{{CountryCode: "test"}}})
	builds := 0
	build := func([]byte) ([]*config_parser.Param, error) {
		builds++
		return []*config_parser.Param{{Val: "test.example"}}, nil
	}
	first := NewDatReaderOptimizer(t.Context(), nil)
	next := NewDatReaderOptimizer(t.Context(), nil)
	for _, step := range []struct {
		reader *DatReaderOptimizer
		want   int
	}{{first, 1}, {first, 1}, {next, 2}, {first, 2}, {next, 2}} {
		if _, err := step.reader.cachedDatParams(path, "test", "GeoSite", "", build); err != nil {
			t.Fatal(err)
		}
		if builds != step.want {
			t.Fatalf("built %d times, want %d: preparations must own their cache", builds, step.want)
		}
	}
}

func TestDatParamsCacheBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geosite.dat")
	writeDatFixture(t, path, &geodata.GeoSiteList{Entry: []*geodata.GeoSite{{CountryCode: "test"}}})
	for _, limit := range []string{"entries", "bytes"} {
		t.Run(limit, func(t *testing.T) {
			reader := NewDatReaderOptimizer(t.Context(), nil)
			value, retained := "test.example", datParamsCacheEntries
			if limit == "bytes" {
				value, retained = strings.Repeat("x", datParamsCacheBytes/2), 1
			}
			builds := 0
			build := func([]byte) ([]*config_parser.Param, error) {
				builds++
				return []*config_parser.Param{{Val: value}}, nil
			}
			load := func(attribute string) {
				t.Helper()
				params, err := reader.cachedDatParams(path, "test", "GeoSite", attribute, build)
				if err != nil || len(params) != 1 || params[0].Val != value {
					t.Fatalf("expansion at capacity: %v", err)
				}
			}
			for i := range retained {
				load(fmt.Sprint(i))
			}
			load("overflow")
			load("overflow")
			load("0")
			if builds != retained+2 {
				t.Fatalf("built %d times, want %d: overflow must expand without evicting cached results", builds, retained+2)
			}
		})
	}
}

func datParamsBenchmarkFinder(b *testing.B) *assets.LocationFinder {
	b.Helper()
	dir := b.TempDir()
	site := &geodata.GeoSite{CountryCode: "bench"}
	for i := range 4096 {
		site.Domain = append(site.Domain, &geodata.Domain{Type: geodata.Domain_Full, Value: fmt.Sprintf("d%d.example.com", i)})
	}
	writeDatFixture(b, filepath.Join(dir, "geosite.dat"), &geodata.GeoSiteList{Entry: []*geodata.GeoSite{site}})
	return assets.NewLocationFinder([]string{dir})
}

func BenchmarkDatParamsExpansion(b *testing.B) {
	reader := NewDatReaderOptimizer(b.Context(), datParamsBenchmarkFinder(b))
	if _, err := reader.loadGeoSite("geosite", "bench"); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := reader.loadGeoSite("geosite", "bench"); err != nil {
			b.Fatal(err)
		}
	}
}

// A new preparation pays for its first expansion even when the file index is
// warm. Measure that cost as well as repeated references within a preparation.
func BenchmarkDatParamsPreparation(b *testing.B) {
	finder := datParamsBenchmarkFinder(b)
	for _, references := range []int{1, 8} {
		b.Run(fmt.Sprintf("references=%d", references), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				reader := NewDatReaderOptimizer(b.Context(), finder)
				for range references {
					if _, err := reader.loadGeoSite("geosite", "bench"); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
