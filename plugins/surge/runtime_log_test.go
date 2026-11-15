// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"strings"
	"testing"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
)

func TestScriptLogDisabledDoesNotAllocate(t *testing.T) {
	logger := testSurgeLogger(func(*log.Entry) { t.Error("disabled log reached the hook") })
	logger.Logger.SetLevel(log.WarnLevel)
	parts := []string{strings.Repeat("界", maxScriptLogText), "subtitle", "body"}
	for _, entry := range []*log.Entry{nil, logger} {
		execution := &scriptExecution{runtime: &Runtime{opts: RuntimeOptions{Logger: entry}}}
		if allocations := testing.AllocsPerRun(100, func() { execution.log(log.InfoLevel, parts...) }); allocations != 0 {
			t.Fatalf("disabled logging allocated %g objects per call", allocations)
		}
	}
}

func TestScriptLogBounds(t *testing.T) {
	for _, args := range [][]string{
		{"log", "error", strings.Repeat("界", maxScriptLogText)},
		{"notify", "title", "subtitle", strings.Repeat("界", maxScriptLogText)},
		{"notify", strings.Repeat("x", maxScriptLogText), "", ""},
	} {
		var entries []*log.Entry
		rt := &Runtime{opts: RuntimeOptions{Logger: testSurgeLogger(func(e *log.Entry) { entries = append(entries, e) })}}
		execution := &scriptExecution{runtime: rt, ctx: t.Context(), scope: testDeviceScope}
		if _, err := execution.hostCall(args); err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("entries=%d", len(entries))
		}
		entry := entries[0]
		if len(entry.Message) > maxScriptLogText || !utf8.ValidString(entry.Message) || entry.Data["truncated"] != true {
			t.Fatalf("unbounded log: bytes=%d fields=%v", len(entry.Message), entry.Data)
		}
		if entry.Data["scope"] != "device" || entry.Data["mac"] != testDeviceName {
			t.Fatalf("bounded log lost execution scope: %v", entry.Data)
		}
	}
}
