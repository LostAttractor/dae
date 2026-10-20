// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"maps"
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/common/macaddr"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
)

func TestClientMembershipChanges(t *testing.T) {
	const a, b, c = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"
	for _, test := range []struct {
		name           string
		previous, next map[string][]string
		sets, affected []string
	}{
		{"unchanged", map[string][]string{"first": {a, b}}, map[string][]string{"first": {a, b}}, nil, nil},
		{"added and removed", map[string][]string{"first": {a, b}}, map[string][]string{"first": {b, c}}, []string{"first"}, []string{a, c}},
		{"moved between routes", map[string][]string{"first": {a}}, map[string][]string{"second": {a}}, []string{"first", "second"}, []string{a}},
		{"reordered", map[string][]string{"first": {a, b}}, map[string][]string{"first": {b, a}}, []string{"first"}, nil},
		{"export only", nil, map[string][]string{"export": {a}}, []string{"export"}, nil},
		{"unused", nil, map[string][]string{"unused": {a}}, nil, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			plane := &ControlPlane{
				routingState: &routingState{clientSetSlots: map[string]int{"first": 0, "second": 1}},
				clients:      map[string]config.Client{"export": {IPSet: "exported"}},
			}
			previous, next := settings.Snapshot{Clients: test.previous}, settings.Snapshot{Clients: test.next}
			changes, affected := plane.clientMembershipChanges(previous, next)
			var names []string
			for _, change := range changes {
				names = append(names, change.name)
				if !reflect.DeepEqual(change.previous, previous.Members(change.name)) || !reflect.DeepEqual(change.next, next.Members(change.name)) {
					t.Fatalf("change lost application or rollback members: %+v", change)
				}
			}
			if !reflect.DeepEqual(names, test.sets) {
				t.Fatalf("changed sets = %v, want %v", names, test.sets)
			}
			want := make(map[[6]byte]bool)
			for _, text := range test.affected {
				mac, err := macaddr.ParseClient(text)
				if err != nil {
					t.Fatal(err)
				}
				want[mac] = true
			}
			if !maps.Equal(affected, want) {
				t.Fatalf("affected devices = %v, want %v", affected, want)
			}
		})
	}
}
