// SPDX-License-Identifier: AGPL-3.0-only

package api

// NetworkIndex is the stable wire-array order. It is independent of routing internals.
type NetworkIndex int

const (
	NetworkTCP4 NetworkIndex = iota
	NetworkTCP6
	NetworkUDP4
	NetworkUDP6
	NetworkTypeCount = 4
)

func (n NetworkIndex) String() string {
	switch n {
	case NetworkTCP4:
		return "tcp4"
	case NetworkTCP6:
		return "tcp6"
	case NetworkUDP4:
		return "udp4"
	case NetworkUDP6:
		return "udp6"
	}
	return "unknown"
}
