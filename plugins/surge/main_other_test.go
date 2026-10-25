//go:build !cgo || surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"os"
	"testing"

	"github.com/daeuniverse/dae/internal/testutil"
)

func TestMain(m *testing.M) {
	testutil.InstallOfflineResolver()
	os.Exit(m.Run())
}
