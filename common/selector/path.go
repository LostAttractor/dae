// SPDX-License-Identifier: AGPL-3.0-only

// Package selector describes saved manual choices independently of dialer runtimes.
package selector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

type Node struct {
	Source      string `json:"source"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	// Exact prevents a same-source namesake from replacing a selected duplicate.
	Exact bool `json:"exact,omitzero"`
}

// Path contains only the user's node references and explicit entrance choice.
// A nil Mark means inheritance, not the current effective global mark.
type Path struct {
	Nodes     []Node  `json:"nodes"`
	IPVersion int     `json:"ipversion,omitzero"`
	Interface string  `json:"interface,omitempty"`
	Mark      *uint32 `json:"mark,omitempty"`
}

func Fingerprint(link string) string {
	sum := sha256.Sum256([]byte(link))
	return hex.EncodeToString(sum[:])
}

func SubscriptionSource(tag, link string) string {
	if tag != "" {
		return "subscription:" + tag
	}
	return "subscription-url:" + Fingerprint(link)
}

func (p *Path) Clone() *Path {
	if p == nil {
		return nil
	}
	copy := *p
	copy.Nodes = slices.Clone(p.Nodes)
	if p.Mark != nil {
		copy.Mark = new(*p.Mark)
	}
	return &copy
}

func (p *Path) Validate() error {
	if p == nil || len(p.Nodes) == 0 || len(p.Nodes) > 16 {
		return fmt.Errorf("selector path requires between 1 and 16 nodes")
	}
	if p.IPVersion != 0 && p.IPVersion != 4 && p.IPVersion != 6 {
		return fmt.Errorf("selector path ipversion must be 4 or 6")
	}
	for _, node := range p.Nodes {
		fingerprint, err := hex.DecodeString(node.Fingerprint)
		if node.Source == "" || node.Name == "" && !node.Exact || err != nil || len(fingerprint) != sha256.Size {
			return fmt.Errorf("selector node requires source, a name or exact matching, and a SHA-256 fingerprint")
		}
	}
	return nil
}

// Matches first uses connection fingerprints, then permits a unique named node
// to follow subscription updates. Exact nodes must never take that second path.
func (p *Path) Matches(candidate *Path, fingerprints bool) bool {
	if p == nil || candidate == nil || len(p.Nodes) != len(candidate.Nodes) ||
		p.IPVersion != candidate.IPVersion || p.Interface != candidate.Interface ||
		(p.Mark == nil) != (candidate.Mark == nil) || p.Mark != nil && *p.Mark != *candidate.Mark {
		return false
	}
	for i, node := range p.Nodes {
		other := candidate.Nodes[i]
		if node.Source != other.Source || node.Name != other.Name ||
			(fingerprints || node.Exact) && node.Fingerprint != other.Fingerprint {
			return false
		}
	}
	return true
}

func (p *Path) String() string {
	if p == nil {
		return ""
	}
	names := make([]string, 0, len(p.Nodes))
	for _, node := range p.Nodes {
		name := node.Name
		if name == "" {
			name = "Unnamed node"
		}
		names = append(names, name)
	}
	name := strings.Join(names, " -> ")
	if p.IPVersion != 0 {
		name += fmt.Sprintf(" [IPv%d]", p.IPVersion)
	}
	if p.Interface != "" {
		name += " [interface=" + p.Interface + "]"
	}
	if p.Mark != nil {
		name += fmt.Sprintf(" [mark=0x%x]", *p.Mark)
	}
	return name
}
