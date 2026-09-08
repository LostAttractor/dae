package api

import (
	jsonv1 "encoding/json"
	jsonv2 "encoding/json/v2"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

func TestStatusRecoveryMetadataRoundTrip(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	resource := netproxy.ResourceRef{OwnerID: 2, ResourceID: 3, Generation: 4}
	node := NodeStatus{
		ID: "node", Revision: 17, ObservedSessionSeq: 8,
		SessionDetail: &SessionStatus{State: "disconnected", Seq: 8, ReadinessVersion: 3, Resource: resource, EpisodeID: 2},
		Recovery: dialer.RecoverySnapshot{Executor: netproxy.RecoveryDaemon,
			Phase: dialer.RecoveryBackoff, Verification: "pending", Attempt: 2,
			RetryAt: now.Add(1700 * time.Millisecond)},
		Failure: &dialer.FailureSnapshot{EpisodeID: 2, Resource: resource,
			Scope: netproxy.ScopeSharedResource, Layer: netproxy.LayerQUIC,
			Phase: netproxy.OpRead, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonReset,
			Code: "42", OccurredAt: now, Message: "peer reset"},
	}
	encoded, err := jsonv2.Marshal(node, jsonv1.FormatDurationAsNano(true))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"owner_id":2`) || !strings.Contains(string(encoded), `"state":"disconnected"`) || strings.Contains(string(encoded), `"session":`) {
		t.Fatalf("resource is not a stable JSON DTO: %s", encoded)
	}
	var decoded NodeStatus
	if err := jsonv2.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(node.Recovery, decoded.Recovery) || !reflect.DeepEqual(node.Failure, decoded.Failure) ||
		!reflect.DeepEqual(node.SessionDetail, decoded.SessionDetail) || node.Revision != decoded.Revision || node.ObservedSessionSeq != decoded.ObservedSessionSeq {
		t.Fatalf("recovery metadata changed: %+v", decoded)
	}
}
