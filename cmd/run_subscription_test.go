package cmd

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
)

func TestPersistentSubscriptionTagsRejectDuplicates(t *testing.T) {
	_, err := persistentSubscriptionTags([]config.KeyableString{
		"shared:http-file://example.com/one",
		"shared:https-file://example.com/two",
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate persistent subscription tag") {
		t.Fatalf("persistentSubscriptionTags error = %v, want duplicate tag error", err)
	}
}
