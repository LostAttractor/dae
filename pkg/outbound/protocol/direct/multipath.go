package direct

import (
	"net/netip"
	"sync"
)

// multipathMemoryLimit bounds remembered destinations; beyond it an arbitrary
// settled one is forgotten and probed again when next dialed.
const multipathMemoryLimit = 4096

type multipathKey struct {
	mark  int
	iface string
	addr  netip.AddrPort
}

type multipathState uint8

const (
	multipathUnknown multipathState = iota
	multipathProbing
	multipathCapable
	multipathIncapable
)

// MultipathMemory remembers per mark, interface and destination whether an
// MPTCP dial negotiated MPTCP. A Linux MPTCP socket whose peer answers with
// plain TCP stays a fallen-back MPTCP socket for life, and the kernel keeps
// no per-destination memory, so destinations that did not negotiate MPTCP
// are dialed as plain TCP. The zero value is ready to use.
type MultipathMemory struct {
	mu     sync.Mutex
	states map[multipathKey]multipathState
}

// Reset forgets every destination. Dials in flight settle into the dropped
// table.
func (m *MultipathMemory) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states = nil
}

// choose reports whether to dial key with MPTCP, and the table its result
// settles into. One dial at a time probes an unknown destination; others use
// plain TCP meanwhile.
func (m *MultipathMemory) choose(key multipathKey) (map[multipathKey]multipathState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.states[key] {
	case multipathCapable:
		return m.states, true
	case multipathProbing, multipathIncapable:
		return nil, false
	}
	if m.states == nil {
		m.states = make(map[multipathKey]multipathState)
	}
	if len(m.states) >= multipathMemoryLimit {
		for other, state := range m.states {
			if state != multipathProbing {
				delete(m.states, other)
				break
			}
		}
		if len(m.states) >= multipathMemoryLimit {
			return nil, false
		}
	}
	m.states[key] = multipathProbing
	return m.states, true
}

// settle records an MPTCP dial of key. multipathUnknown, for a dial that
// failed or was canceled, teaches nothing: a probe leaves key unknown.
func (m *MultipathMemory) settle(table map[multipathKey]multipathState, key multipathKey, result multipathState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case result != multipathUnknown:
		table[key] = result
	case table[key] == multipathProbing:
		delete(table, key)
	}
}
