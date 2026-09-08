package geodata

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestEmitBytesRejectsMalformedLengths(t *testing.T) {
	for name, data := range map[string][]byte{
		"entry beyond file":      {10, 127, 10, 2, 'c', 'n'},
		"empty entry":            {10, 0},
		"country beyond entry":   {10, 2, 10, 4, 'c', 'n', 'u', 's'},
		"maximum country length": append([]byte{10, 12, 10}, append(protowire.AppendVarint(nil, ^uint64(0)), 'x')...),
		"overflowing varint":     append([]byte{10}, bytes.Repeat([]byte{255}, 10)...),
		"truncated varint":       {10, 128},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := emitBytes(bytes.NewReader(data), "cn"); err == nil || errors.Is(err, errCodeNotFound) {
				t.Fatalf("malformed file returned %v", err)
			}
		})
	}
}

type shortGeodataReader struct{ *bytes.Reader }

func (r shortGeodataReader) Read(p []byte) (int, error) {
	return r.Reader.Read(p[:min(len(p), 1)])
}

func TestEmitBytesSkipsUnmatchedEntriesAndHandlesShortReads(t *testing.T) {
	list := &GeoIPList{Entry: []*GeoIP{{CountryCode: "us"}, {CountryCode: "CN", InverseMatch: true}}}
	data, err := proto.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := emitBytes(shortGeodataReader{bytes.NewReader(data)}, "cn")
	if err != nil {
		t.Fatal(err)
	}
	var decoded GeoIP
	if err := proto.Unmarshal(entry, &decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(&decoded, list.Entry[1]) {
		t.Fatalf("selected wrong entry: %v", &decoded)
	}
	if _, err := emitBytes(bytes.NewReader(data), "missing"); !errors.Is(err, errCodeNotFound) {
		t.Fatal(err)
	}
}

type failingGeodataSeeker struct {
	*bytes.Reader
	fail, calls int
}

func (r *failingGeodataSeeker) Seek(offset int64, whence int) (int64, error) {
	r.calls++
	if r.calls == r.fail {
		return 0, errors.New("seek failed")
	}
	return r.Reader.Seek(offset, whence)
}

func TestEmitBytesPropagatesSeekFailure(t *testing.T) {
	for fail := 1; fail <= 4; fail++ {
		reader := &failingGeodataSeeker{Reader: bytes.NewReader([]byte{10, 4, 10, 2, 'c', 'n'}), fail: fail}
		if _, err := emitBytes(reader, "cn"); !errors.Is(err, errFailedToReadBytes) {
			t.Fatalf("seek %d: %v", fail, err)
		}
	}
}

func TestUnmarshalGeodataFallsBackForReorderedFields(t *testing.T) {
	// InverseMatch precedes CountryCode: valid protobuf outside the fast layout.
	data := []byte{10, 6, 24, 1, 10, 2, 'c', 'n'}
	path := filepath.Join(t.TempDir(), "geoip.dat")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	entry, err := UnmarshalGeoIp(path, "CN")
	if err != nil {
		t.Fatal(err)
	}
	if entry.CountryCode != "cn" || !entry.InverseMatch {
		t.Fatalf("wrong fallback entry: %v", entry)
	}
	if _, err := Decode(path, "cn"); !errors.Is(err, errInvalidGeodataFile) {
		t.Fatal(err)
	}
}
