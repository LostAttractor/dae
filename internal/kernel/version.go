// SPDX-License-Identifier: AGPL-3.0-only

package kernel

import (
	"fmt"

	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
)

// CheckVersion verifies that the running kernel meets dae's minimum requirement.
func CheckVersion() error {
	version, err := internal.KernelVersion()
	if err != nil {
		return fmt.Errorf("get kernel version: %w", err)
	}
	minimum := internal.Version{6, 13, 0}
	if version.Less(minimum) {
		return fmt.Errorf("kernel %s requires an upgrade to Linux %s or newer", version, minimum)
	}
	return nil
}
