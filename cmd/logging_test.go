// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestCommandDiagnosticsDoNotEscapeMessagesAgain(t *testing.T) {
	for name, logger := range map[string]*log.Logger{"lifecycle": std, "early global": log.StandardLogger()} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			previous := logger.Out
			logger.SetOutput(&output)
			t.Cleanup(func() { logger.SetOutput(previous) })

			message := "module \"测试\":\n  resource failed"
			logger.WithError(errors.New(message)).Error("initialization \"failed\"")
			got := output.String()
			if !strings.Contains(got, `msg=initialization "failed"`) || !strings.Contains(got, "error="+message) {
				t.Fatalf("command diagnostics escaped quoted or multiline text again:\n%s", got)
			}
		})
	}
}
