// SPDX-License-Identifier: AGPL-3.0-only

package api

// ClientIdentity is verified ingress evidence supplied by the runtime, never
// caller input. IP links have no device MAC.
type ClientIdentity struct {
	LinkType        string
	MAC             [6]byte
	IfIndex         uint32
	PhysicalIfIndex uint32
}
