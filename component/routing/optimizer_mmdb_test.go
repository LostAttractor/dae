// SPDX-License-Identifier: AGPL-3.0-only

package routing

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/oschwald/maxminddb-golang/v2"
)

type mmdbTestNetwork struct {
	prefix string
	record int
}

// Build a small 24-bit MMDB trie from locally defined records. No external
// database or writer is needed by the tests.
func writeTestMMDB(t testing.TB, version int, networks []mmdbTestNetwork, records ...[]byte) string {
	t.Helper()
	nodes := [][2]int{{-1, -1}}
	for _, network := range networks {
		prefix := netip.MustParsePrefix(network.prefix)
		ip := prefix.Addr().As16()
		start, bits := 0, prefix.Bits()
		if prefix.Addr().Is4() {
			if version == 4 {
				start = 96
			} else {
				ip[10], ip[11] = 0, 0
				bits += 96
			}
		}
		node := 0
		for bit := range bits {
			side := int(ip[(start+bit)/8] >> (7 - (start+bit)%8) & 1)
			if bit == bits-1 {
				nodes[node][side] = -2 - network.record
				break
			}
			next := nodes[node][side]
			if next < 0 {
				next = len(nodes)
				nodes[node][side] = next
				nodes = append(nodes, [2]int{-1, -1})
			}
			node = next
		}
	}
	var data []byte
	offsets := make([]int, len(records))
	for i, record := range records {
		offsets[i] = len(data)
		data = append(data, record...)
	}
	var content []byte
	for _, node := range nodes {
		for _, pointer := range node {
			if pointer == -1 {
				pointer = len(nodes)
			} else if pointer < -1 {
				pointer = len(nodes) + 16 + offsets[-2-pointer]
			}
			content = append(content, byte(pointer>>16), byte(pointer>>8), byte(pointer))
		}
	}
	content = append(content, make([]byte, 16)...)
	content = append(content, data...)
	content = append(content, []byte("\xab\xcd\xefMaxMind.com")...)
	content = append(content, mmdbTestMap(
		"binary_format_major_version", mmdbTestUint(2),
		"binary_format_minor_version", mmdbTestUint(0),
		"database_type", mmdbTestString("dae-test"),
		"ip_version", mmdbTestUint(version),
		"record_size", mmdbTestUint(24),
		"node_count", mmdbTestUint(len(nodes)),
	)...)
	path := filepath.Join(t.TempDir(), "geoip.mmdb")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mmdbTestString(s string) []byte { return append([]byte{0x40 | byte(len(s))}, s...) }

func mmdbTestUint(n int) []byte {
	return binary.BigEndian.AppendUint32([]byte{0xc4}, uint32(n))
}

func mmdbTestMap(pairs ...any) []byte {
	data := []byte{0xe0 | byte(len(pairs)/2)}
	for i := 0; i < len(pairs); i += 2 {
		data = append(data, mmdbTestString(pairs[i].(string))...)
		data = append(data, pairs[i+1].([]byte)...)
	}
	return data
}

func TestMMDBFieldsAndPreparationScope(t *testing.T) {
	path := writeTestMMDB(t, 6, []mmdbTestNetwork{
		{"192.0.2.0/24", 0}, {"198.51.100.0/24", 0},
		{"203.0.113.0/24", 1}, {"2001:db8::/32", 0}, {"2001:db9::/32", 2},
	}, mmdbTestMap("country", mmdbTestString("CN"), "continent", mmdbTestString("Asia")),
		mmdbTestMap("country", mmdbTestString("US"), "continent", mmdbTestString("America")),
		mmdbTestMap("continent", mmdbTestString("Asia")))
	db, err := maxminddb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := db.Lookup(netip.MustParseAddr("192.0.2.1")).Prefix(); got.String() != "192.0.2.0/24" {
		t.Fatal(got)
	}
	db.Close()
	reader := NewDatReaderOptimizer(t.Context(), assets.NewLocationFinder([]string{filepath.Dir(path)}))
	for _, tc := range []struct {
		field, value string
		want         []string
	}{
		{"country", "cn", []string{"192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32"}},
		{"country", "us", []string{"203.0.113.0/24"}},
		{"country", "absent", nil},
		{"continent", "asia", []string{"192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32", "2001:db9::/32"}},
		{"missing", "cn", nil},
	} {
		params, err := reader.loadMMDB("geoip", tc.field, tc.value)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, param := range params {
			got = append(got, param.Val)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s=%s: got %v, want %v", tc.field, tc.value, got, tc.want)
		}
	}
	params, err := reader.loadMMDB("geoip", "country", "cn")
	if err != nil {
		t.Fatal(err)
	}
	params[0].Val = "changed"
	again, err := reader.loadMMDB("geoip", "country", "cn")
	if err != nil || again[0].Val != "192.0.2.0/24" {
		t.Fatalf("cache was mutated: %v, %v", again, err)
	}
	if err := os.WriteFile(path, []byte("invalid database"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.loadMMDB("geoip", "country", "cn"); err != nil {
		t.Fatalf("preparation cache reopened database: %v", err)
	}
	fresh := NewDatReaderOptimizer(t.Context(), assets.NewLocationFinder([]string{filepath.Dir(path)}))
	if _, err := fresh.loadMMDB("geoip", "country", "cn"); err == nil {
		t.Fatal("new preparation used a stale cache")
	}
}

func TestMMDBRejectsInvalidField(t *testing.T) {
	path := writeTestMMDB(t, 4, []mmdbTestNetwork{{"192.0.2.0/24", 0}}, mmdbTestMap("country", mmdbTestUint(42)))
	reader := NewDatReaderOptimizer(t.Context(), assets.NewLocationFinder([]string{filepath.Dir(path)}))
	if _, err := reader.loadMMDB("geoip", "country", "cn"); err == nil {
		t.Fatal("non-string field accepted")
	}
}

func TestMMDBRejectsBrokenTreeAfterCachedRecord(t *testing.T) {
	path := writeTestMMDB(t, 4, []mmdbTestNetwork{{"0.0.0.0/1", 0}, {"128.0.0.0/1", 0}}, mmdbTestMap("country", mmdbTestString("CN")))
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The left leaf decodes offset zero successfully. Make the right child
	// point back to the root so iteration later fails with the same offset.
	clear(contents[3:6])
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	reader := NewDatReaderOptimizer(t.Context(), assets.NewLocationFinder([]string{filepath.Dir(path)}))
	if _, err := reader.loadMMDB("geoip", "country", "cn"); err == nil {
		t.Fatal("cached record hid a malformed search tree")
	}
	if len(reader.mmdbCaches) != 0 {
		t.Fatal("cached partial results from a malformed database")
	}
}

type mmdbCancelContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (ctx *mmdbCancelContext) Err() error {
	ctx.remaining--
	if ctx.remaining == 0 {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestMMDBCanceledScanDoesNotCachePartialResults(t *testing.T) {
	path := writeTestMMDB(t, 4, []mmdbTestNetwork{{"192.0.2.0/24", 0}, {"198.51.100.0/24", 0}}, mmdbTestMap("country", mmdbTestString("CN")))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reader := NewDatReaderOptimizer(&mmdbCancelContext{Context: ctx, cancel: cancel, remaining: 3}, assets.NewLocationFinder([]string{filepath.Dir(path)}))
	if _, err := reader.loadMMDB("geoip", "country", "cn"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation during traversal, got %v", err)
	}
	if len(reader.mmdbCaches) != 0 {
		t.Fatal("cached a canceled scan")
	}
	reader.ctx = t.Context()
	if params, err := reader.loadMMDB("geoip", "country", "cn"); err != nil || len(params) != 2 {
		t.Fatalf("scan after cancellation: %v, %v", params, err)
	}
}

func BenchmarkMMDBLoad(b *testing.B) {
	networks := make([]mmdbTestNetwork, 1<<16)
	for i := range networks {
		networks[i] = mmdbTestNetwork{fmt.Sprintf("%d.%d.0.0/16", i>>8, i&255), i % 16}
	}
	var records [][]byte
	for i := range 16 {
		records = append(records, mmdbTestMap("country", mmdbTestString(fmt.Sprintf("c%d", i))))
	}
	path := writeTestMMDB(b, 4, networks, records...)
	finder := assets.NewLocationFinder([]string{filepath.Dir(path)})
	b.ReportAllocs()
	for b.Loop() {
		reader := NewDatReaderOptimizer(b.Context(), finder)
		params, err := reader.loadMMDB("geoip", "country", "c0")
		if err != nil {
			b.Fatal(err)
		}
		if len(params) != len(networks)/16 {
			b.Fatal(len(params))
		}
	}
}
