// SPDX-License-Identifier: AGPL-3.0-only

// Package macaddr parses Ethernet addresses and validates client identities.
package macaddr

import (
	"fmt"
	"net"
)

// Parse accepts the six-byte forms supported by net.ParseMAC. Callers that store
// addresses canonically can compare net.HardwareAddr(mac[:]).String() to input.
func Parse(text string) ([6]byte, error) {
	mac, err := net.ParseMAC(text)
	if err != nil || len(mac) != 6 {
		return [6]byte{}, fmt.Errorf("expected a 6-byte Ethernet MAC address")
	}
	return [6]byte(mac), nil
}

func ValidClient(mac [6]byte) bool { return mac != [6]byte{} && mac[0]&1 == 0 }

// ParseClient additionally rejects zero, multicast and broadcast identities.
func ParseClient(text string) ([6]byte, error) {
	mac, err := Parse(text)
	if err != nil || !ValidClient(mac) {
		return [6]byte{}, fmt.Errorf("expected a nonzero unicast Ethernet MAC")
	}
	return mac, nil
}
