//go:build trace && (amd64 || arm64 || riscv64 || loong64 || ppc64 || ppc64le)

package cmd

import (
	"strings"
	"testing"
)

func TestTraceRejectsInvalidFlagsWithoutExiting(t *testing.T) {
	command, _, err := rootCmd.Find([]string{"trace"})
	if err != nil || command.RunE == nil {
		t.Fatalf("trace command is unavailable: %v", err)
	}
	previousIPv4, previousIPv6, previousProto := IPv4, IPv6, L4Proto
	t.Cleanup(func() { IPv4, IPv6, L4Proto = previousIPv4, previousIPv6, previousProto })
	IPv4, IPv6, L4Proto = true, true, "tcp"
	if err := command.RunE(command, nil); err == nil || !strings.Contains(err.Error(), "cannot be set at the same time") {
		t.Fatalf("conflicting flags error: %v", err)
	}
	IPv4, IPv6, L4Proto = false, false, "icmp"
	if err := command.RunE(command, nil); err == nil || !strings.Contains(err.Error(), "use tcp or udp") {
		t.Fatalf("unsupported protocol error: %v", err)
	}
}
