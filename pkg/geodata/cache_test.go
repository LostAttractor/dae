// SPDX-License-Identifier: AGPL-3.0-only

package geodata

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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
