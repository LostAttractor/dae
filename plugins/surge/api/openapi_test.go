// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/internal/testutil"
)

func TestOpenAPIMatchesWireTypes(t *testing.T) {
	schemas := testutil.LoadSchemas(t, "../../../docs/api/openapi.json", "openapi.json")
	schemas.Check(t, reflect.TypeFor[SurgeStatus]())
}
