package netproxy

import (
	"iter"
	"slices"
	"sync/atomic"
)

// LanePlacement counts the user streams a pooled transport placed in a
// lane, by how: on a session of the lane, on a spare session, or falling
// back to a session of another lane.
type LanePlacement struct {
	lane, result string
	total        atomic.Uint64
}

var lanePlacements []*LanePlacement

// NewLanePlacement registers the counter of a lane and result. It is called
// during package initialization, once for each pair.
func NewLanePlacement(lane, result string) *LanePlacement {
	if slices.ContainsFunc(lanePlacements, func(p *LanePlacement) bool { return p.lane == lane && p.result == result }) {
		panic("netproxy: duplicate lane placement counter " + lane + "/" + result)
	}
	p := &LanePlacement{lane: lane, result: result}
	lanePlacements = append(lanePlacements, p)
	return p
}

// LanePlacements yields every registered counter.
func LanePlacements() iter.Seq[*LanePlacement] { return slices.Values(lanePlacements) }

func (p *LanePlacement) Lane() string   { return p.lane }
func (p *LanePlacement) Result() string { return p.result }
func (p *LanePlacement) Load() uint64   { return p.total.Load() }
func (p *LanePlacement) Add(n uint64)   { p.total.Add(n) }
