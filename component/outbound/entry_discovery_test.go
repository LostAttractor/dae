// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestEntryDiscoveryCacheIsolation(t *testing.T) {
	var paths []*PathSpec
	for _, entry := range []EntryOptions{
		{}, {}, {Mark: new(uint32(0))}, {Mark: new(uint32(32))},
		{Interface: "wan4"}, {Interface: "wan6"}, {Interface: "wan6", Families: new(uint8(family4))},
	} {
		paths = append(paths, &PathSpec{Nodes: []*NodeInfo{{Property: &dialer.Property{Address: "entry.test:443"}}}, Entry: entry})
	}
	var calls atomic.Int32
	variants, err := expandIPVariants(t.Context(), paths, func(_ context.Context, path *PathSpec) (uint8, error) {
		calls.Add(1)
		if path.Entry.Interface == "wan6" || path.Entry.Mark != nil && *path.Entry.Mark == 32 {
			return family6, nil
		}
		if path.Entry.Mark != nil && *path.Entry.Mark == 0 {
			return 0, nil
		}
		return family4, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []int
	for _, variant := range variants {
		got = append(got, variant.IPVersion)
	}
	if !reflect.DeepEqual(got, []int{4, 4, 6, 4, 6}) {
		t.Fatalf("entry cache crossed mark/interface boundaries or changed declaration order: %v", got)
	}
	if calls.Load() != 5 {
		t.Fatalf("entry discovery calls = %d, want 5 unique egresses", calls.Load())
	}
}

func TestEntryDiscoveryCanceledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	path := &PathSpec{Nodes: []*NodeInfo{{Property: &dialer.Property{Address: "entry.test:443"}}}}
	var calls atomic.Int32
	_, err := expandIPVariants(ctx, []*PathSpec{path}, func(context.Context, *PathSpec) (uint8, error) {
		calls.Add(1)
		return allFamilies, nil
	})
	if !errors.Is(err, context.Canceled) || calls.Load() != 0 {
		t.Fatalf("canceled discovery started work: calls=%d error=%v", calls.Load(), err)
	}
}

func TestEntryDiscoveryCanceledDuringWork(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var paths []*PathSpec
	for i := range 64 {
		paths = append(paths, &PathSpec{Nodes: []*NodeInfo{{Property: &dialer.Property{Address: fmt.Sprintf("entry-%d.test:443", i)}}}})
	}
	var calls atomic.Int32
	_, err := expandIPVariants(ctx, paths, func(context.Context, *PathSpec) (uint8, error) {
		calls.Add(1)
		cancel()
		return 0, ctx.Err()
	})
	if !errors.Is(err, context.Canceled) || calls.Load() > maxConcurrentEntryLookups {
		t.Fatalf("canceled discovery kept admitting queued work: calls=%d error=%v", calls.Load(), err)
	}
}

func TestEntryVariantLabelsAndIdentity(t *testing.T) {
	path := &PathSpec{Nodes: []*NodeInfo{{Property: &dialer.Property{Name: "entry", Address: "entry.test:443"}}}}
	var singleID string
	for _, mask := range []uint8{family4, allFamilies, family6} {
		variants, err := expandIPVariants(t.Context(), []*PathSpec{path}, func(context.Context, *PathSpec) (uint8, error) {
			return mask, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, variant := range variants {
			d, err := new(DialerSet).BuildPath(variant, new(dialer.GlobalOption), t.Name())
			if err != nil {
				t.Fatal(err)
			}
			hasLabel := strings.Contains(d.Name, "[IPv")
			if hasLabel != (mask == allFamilies) {
				t.Errorf("single/dual-stack display mismatch: family mask=%d name=%q", mask, d.Name)
			}
			if mask == family4 {
				singleID = d.StatsID()
			} else if variant.IPVersion == 4 && d.StatsID() != singleID {
				t.Error("adding the IPv6 sibling changed the IPv4 identity")
			}
			_ = d.Close()
		}
	}
}
