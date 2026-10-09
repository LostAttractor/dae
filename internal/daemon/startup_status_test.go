// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/api"
	log "github.com/sirupsen/logrus"
)

func TestStartupNodeStatusLogsOnlyAtDebug(t *testing.T) {
	var output bytes.Buffer
	logger := log.StandardLogger()
	previousOutput, previousLevel := logger.Out, logger.GetLevel()
	t.Cleanup(func() {
		logger.SetOutput(previousOutput)
		logger.SetLevel(previousLevel)
	})
	logger.SetOutput(&output)
	groups := []api.GroupStatus{{Name: "proxy", Nodes: []api.NodeStatus{{
		Name: "startup-node", ChecksConnectivity: true, InitialCheckDone: true,
		Availability: api.Availability{Seen: true},
	}}}}
	logger.SetLevel(log.InfoLevel)
	logStartupNodeStatus(groups)
	if output.Len() != 0 {
		t.Fatalf("startup table logged at info: %s", &output)
	}
	logger.SetLevel(log.DebugLevel)
	logStartupNodeStatus(groups)
	if !strings.Contains(output.String(), "startup-node") {
		t.Fatalf("startup table missing at debug: %s", &output)
	}
}
