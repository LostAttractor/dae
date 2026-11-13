// SPDX-License-Identifier: AGPL-3.0-only

package geodata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/resource"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestGeodataCacheFileIdentityAndOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geo.dat")
	encode := func(inverse bool) []byte {
		data, err := proto.Marshal(&GeoIPList{Entry: []*GeoIP{{CountryCode: "CN", InverseMatch: inverse}, {CountryCode: "k"}}})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	write := func(path string, data []byte) {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(path, encode(false))
	first, err := Decode(path, "cn")
	if err != nil {
		t.Fatal(err)
	}
	first[0] = 0 // a public caller must not corrupt the shared cache
	if _, err := UnmarshalGeoIp(path, "CN"); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(path, "K"); err != nil {
		t.Fatal("index changed EqualFold semantics:", err)
	}
	write(path+".next", encode(true))
	if err := os.Rename(path+".next", path); err != nil {
		t.Fatal(err)
	}
	entry, err := UnmarshalGeoIp(path, "cn")
	if err != nil || !entry.GetInverseMatch() {
		t.Fatalf("atomic replacement used stale data: %v %v", entry, err)
	}
	write(path, encode(false))
	stamp := time.Now().Add(time.Second)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	entry, err = UnmarshalGeoIp(path, "cn")
	if err != nil || entry.GetInverseMatch() {
		t.Fatalf("in-place update used stale data: %v %v", entry, err)
	}
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			if _, err := Decode(path, "cn"); err != nil {
				t.Error(err)
			}
		})
	}
	readers.Wait()
}

func TestBufferedGeodataScanner(t *testing.T) {
	data, err := proto.Marshal(&GeoIPList{Entry: []*GeoIP{{CountryCode: "us"}, {CountryCode: "cn"}}})
	if err != nil {
		t.Fatal(err)
	}
	want, err := emitBytes(bytes.NewReader(data), "cn")
	if err != nil {
		t.Fatal(err)
	}
	got, err := emitBytes(newBufferedSeeker(bytes.NewReader(data)), "cn")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("buffered seeks changed selected entry: %x %v", got, err)
	}
}

func TestGeodataCacheDetectsSameSizeAndTimestampRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geo.dat")
	write := func(domain string) {
		data, err := proto.Marshal(&GeoSiteList{Entry: []*GeoSite{{CountryCode: "cn", Domain: []*Domain{{Value: domain}}}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("old.example")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalGeoSite(path, "cn"); err != nil {
		t.Fatal(err)
	}
	write("new.example")
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	entry, err := UnmarshalGeoSite(path, "cn")
	if err != nil || entry.Domain[0].Value != "new.example" {
		t.Fatalf("same-metadata rewrite returned stale entry: %v %v", entry, err)
	}
}

func frozenGeodataFixture(t testing.TB) string {
	t.Helper()
	data, err := proto.Marshal(&GeoSiteList{Entry: []*GeoSite{
		{CountryCode: "one", Domain: []*Domain{{Type: Domain_Full, Value: "one.example"}}},
		{CountryCode: "two", Domain: []*Domain{{Type: Domain_Full, Value: "two.example"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// A valid unknown field makes the file large without third-party fixture data.
	padding := protowire.AppendString([]byte{10}, "padding")
	padding = protowire.AppendTag(padding, 127, protowire.BytesType)
	padding = protowire.AppendBytes(padding, make([]byte, 8<<20))
	data = protowire.AppendBytes(append(data, 10), padding)
	path := filepath.Join(t.TempDir(), "geo.dat")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFrozenGeodataIndexOwnershipIsolationAndAllocations(t *testing.T) {
	path := frozenGeodataFixture(t)
	record, inputs := resource.WithInputRecording(t.Context())
	first, err := frozenGeodata(record, path)
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := inputs.Encode(&encoded); err != nil {
		t.Fatal(err)
	}
	saved, err := resource.DecodeInputs(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := proto.Marshal(&GeoSiteList{Entry: []*GeoSite{{CountryCode: "one", Domain: []*Domain{{Value: "changed.example"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	other, _ := resource.WithInputRecording(t.Context())
	if got, err := UnmarshalGeoSiteContext(other, path, "one"); err != nil || got.Domain[0].Value != "changed.example" {
		t.Fatalf("new operation retained old bytes: %v, %v", got, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for name, ctx := range map[string]context.Context{
		"record": record,
		"replay": resource.WithInputReplay(t.Context(), saved),
	} {
		t.Run(name, func(t *testing.T) {
			indexed, err := frozenGeodata(ctx, path)
			if err != nil || name == "record" && indexed != first || name == "replay" && indexed == first {
				t.Fatalf("index ownership: %p, %v", indexed, err)
			}
			var workers sync.WaitGroup
			for i := range 16 {
				workers.Go(func() {
					code := []string{"one", "two"}[i%2]
					for range 4 {
						data, err := DecodeContext(ctx, path, code)
						if err != nil {
							t.Error(err)
							return
						}
						var entry GeoSite
						if err := proto.Unmarshal(data, &entry); err != nil || entry.CountryCode != code {
							t.Errorf("wrong selected entry: %v, %v", &entry, err)
						}
						data[0] = 0
					}
				})
			}
			workers.Wait()
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for i := range 32 {
				if _, err := DecodeContext(ctx, path, []string{"one", "two"}[i%2]); err != nil {
					t.Fatal(err)
				}
			}
			runtime.ReadMemStats(&after)
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
				t.Fatalf("32 tiny entries allocated %d bytes from an 8 MiB file", allocated)
			}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if _, err := DecodeContext(canceled, path, "one"); !errors.Is(err, context.Canceled) {
				t.Fatalf("warm index ignored cancellation: %v", err)
			}
		})
	}
}

func TestFrozenGeodataIndexBudgetUsesPrivateScanner(t *testing.T) {
	data, err := proto.Marshal(&GeoIPList{Entry: []*GeoIP{{CountryCode: "one"}, {CountryCode: "two"}}})
	if err != nil {
		t.Fatal(err)
	}
	indexed := &indexedGeodata{data: data}
	indexed.entries, indexed.err = indexGeodataBounded(data, 131)
	if !errors.Is(indexed.err, errGeodataIndexLimit) || indexed.entries != nil {
		t.Fatalf("unbounded or partial index: %v", indexed.err)
	}
	for _, code := range []string{"one", "two", "one"} {
		entry, err := indexed.decode(code)
		if err != nil {
			t.Fatal(err)
		}
		var decoded GeoIP
		if err := proto.Unmarshal(entry, &decoded); err != nil || decoded.CountryCode != code {
			t.Fatalf("bounded scanner changed entry: %v, %v", &decoded, err)
		}
		entry[0] = 0
	}
}

func TestFrozenGeodataIndexBudgetIsSharedAcrossFiles(t *testing.T) {
	ctx, _ := resource.WithInputRecording(t.Context())
	budget := make(frozenGeodataBudget, 1)
	budget <- 131 // Enough for one three-byte code, not one index per file.
	if _, err := resource.DeriveInput(ctx, "geodata/index-budget", func(context.Context) (frozenGeodataBudget, error) { return budget, nil }); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, code := range []string{"one", "two"} {
		data, err := proto.Marshal(&GeoIPList{Entry: []*GeoIP{{CountryCode: code}}})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "geo.dat")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	files := make([]*indexedGeodata, len(paths))
	var workers sync.WaitGroup
	for i, path := range paths {
		workers.Go(func() {
			indexed, err := frozenGeodata(ctx, path)
			if err != nil {
				t.Error(err)
			}
			files[i] = indexed
		})
	}
	workers.Wait()
	indexed := 0
	for i, file := range files {
		if file == nil {
			t.Fatal("missing frozen file")
		}
		if file.err == nil {
			indexed++
		} else if !errors.Is(file.err, errGeodataIndexLimit) {
			t.Fatal(file.err)
		}
		if err := os.Remove(paths[i]); err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeContext(ctx, paths[i], []string{"one", "two"}[i]); err != nil {
			t.Fatalf("budget fallback reopened the file: %v", err)
		}
	}
	if remaining := <-budget; remaining != 0 || indexed != 1 {
		t.Fatalf("per-file budgets leaked: remaining=%d indexed=%d", remaining, indexed)
	}
}

func TestFrozenGeodataIndexBudgetWaitCanBeCanceled(t *testing.T) {
	ctx, _ := resource.WithInputRecording(t.Context())
	budget := make(frozenGeodataBudget, 1) // Another construction owns the permit.
	if _, err := resource.DeriveInput(ctx, "geodata/index-budget", func(context.Context) (frozenGeodataBudget, error) { return budget, nil }); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "geo.dat")
	if err := os.WriteFile(path, []byte{10, 5, 10, 3, 'o', 'n', 'e'}, 0600); err != nil {
		t.Fatal(err)
	}
	waiting, cancel := context.WithTimeout(ctx, time.Millisecond)
	defer cancel()
	if _, err := frozenGeodata(waiting, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("index budget wait ignored cancellation: %v", err)
	}
}

func BenchmarkFrozenGeodataDecode(b *testing.B) {
	path := frozenGeodataFixture(b)
	record, inputs := resource.WithInputRecording(b.Context())
	if _, err := DecodeContext(record, path, "one"); err != nil {
		b.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := inputs.Encode(&encoded); err != nil {
		b.Fatal(err)
	}
	saved, err := resource.DecodeInputs(&encoded)
	if err != nil {
		b.Fatal(err)
	}
	for name, ctx := range map[string]context.Context{"record": record, "replay": resource.WithInputReplay(b.Context(), saved)} {
		b.Run(name, func(b *testing.B) {
			if _, err := DecodeContext(ctx, path, "one"); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				for _, code := range []string{"one", "two"} {
					if _, err := DecodeContext(ctx, path, code); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func BenchmarkGeodataDecode(b *testing.B) {
	list := &GeoIPList{}
	for i := range 512 {
		list.Entry = append(list.Entry, &GeoIP{CountryCode: fmt.Sprintf("code%d", i)})
	}
	data, err := proto.Marshal(list)
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(b.TempDir(), "geo.dat")
	if err := os.WriteFile(path, data, 0600); err != nil {
		b.Fatal(err)
	}
	for _, indexed := range []bool{false, true} {
		b.Run(fmt.Sprintf("indexed=%t", indexed), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var err error
				if indexed {
					_, err = Decode(path, "code511")
				} else {
					var f *os.File
					f, err = os.Open(path)
					if err == nil {
						_, err = emitBytes(f, "code511")
						f.Close()
					}
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
