// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"reflect"
	"testing"

	"github.com/daeuniverse/dae/internal/testutil"
)

// Keep the host wire contract aligned with its editable OpenAPI documents.
func TestOpenAPIMatchesWireTypes(t *testing.T) {
	schemas := testutil.LoadSchemas(t, "../docs/api/openapi.json", "../docs/api/diagnostics.json")
	version := schemas["StatusSnapshot"].Properties["schema"].Const
	if version == nil || *version != StatusSchemaVersion {
		t.Fatal("documented status schema version does not match the wire contract")
	}

	for _, typ := range []reflect.Type{reflect.TypeFor[StatusSnapshot](), reflect.TypeFor[ScriptRunRequest](), reflect.TypeFor[ScriptRunResponse](), reflect.TypeFor[ResourceRefreshStatus](), reflect.TypeFor[Operation](), reflect.TypeFor[OperationRequest](), reflect.TypeFor[SelectorsResponse](), reflect.TypeFor[DeviceState](), reflect.TypeFor[DeviceStatus](), reflect.TypeFor[CertificateTest](), reflect.TypeFor[CertificateTestProof](), reflect.TypeFor[Certificate](), reflect.TypeFor[SelectNodeRequest](), reflect.TypeFor[ProbeRequest](), reflect.TypeFor[ProbeResponse](), reflect.TypeFor[SetMITMRequest]()} {
		schemas.Check(t, typ)
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[ExplainRequest](), reflect.TypeFor[ExplainResponse](), reflect.TypeFor[DeviceContext](), reflect.TypeFor[ClientGroups](), reflect.TypeFor[ManagedDevice](), reflect.TypeFor[ClientImpactRequest](), reflect.TypeFor[ClientImpact]()} {
		schemas.Check(t, typ)
	}
}
