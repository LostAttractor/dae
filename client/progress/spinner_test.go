// SPDX-License-Identifier: AGPL-3.0-only

package progress

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jedib0t/go-pretty/v6/text"
)

func TestSpinnerQuickOperationIsSilent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var output bytes.Buffer
		spinner := start(&output, "Waiting...", func() int { return 80 })
		time.Sleep(showDelay / 2)
		spinner.Stop()
		spinner.Stop()
		time.Sleep(showDelay)
		if output.Len() != 0 {
			t.Fatalf("quick operation emitted %q", output.String())
		}
	})
}

func TestSpinnerUpdatesAndStopsBeforeResults(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var output bytes.Buffer
		spinner := start(&output, "Waiting...", func() int { return 80 })
		defer spinner.Stop()
		time.Sleep(showDelay)
		synctest.Wait()
		if !strings.Contains(output.String(), frames[0]+" Waiting...") {
			t.Fatalf("missing initial frame: %q", output.String())
		}
		spinner.Update("Publishing routing...")
		time.Sleep(frameInterval)
		synctest.Wait()
		if !strings.Contains(output.String(), frames[1]+" Publishing routing...") {
			t.Fatalf("stage did not update: %q", output.String())
		}
		spinner.Stop()
		if !strings.HasSuffix(output.String(), clearLine) {
			t.Fatalf("spinner left its last frame behind: %q", output.String())
		}
		output.WriteString("Done\n")
		finished := output.String()
		time.Sleep(time.Second)
		if output.String() != finished {
			t.Fatalf("renderer wrote after Stop: %q", output.String())
		}
	})
}

func TestSpinnerKeepsStagesOnOneTerminalLine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var output bytes.Buffer
		spinner := start(&output, "准备\n路由\r\t\x1b[31m"+strings.Repeat("网络", 20), func() int { return 12 })
		time.Sleep(showDelay + frameInterval)
		spinner.Stop()
		lines := strings.Split(output.String(), clearLine)
		if len(lines) < 3 {
			t.Fatalf("missing animation: %q", output.String())
		}
		for _, line := range lines {
			if strings.ContainsAny(line, "\n\r\t\x1b") || text.StringWidth(line) > 11 {
				t.Fatalf("frame can corrupt adjacent lines: %q", line)
			}
		}
	})
}

func TestSpinnerRedirectedOutputIsSilent(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	var output bytes.Buffer
	spinner := Start(&output, "Waiting...")
	if spinner.Enabled() {
		t.Fatal("buffer enabled terminal animation")
	}
	spinner.Update("Next stage...")
	spinner.Stop()
	if output.Len() != 0 {
		t.Fatalf("non-terminal received %q", output.String())
	}
	file, err := os.Create(filepath.Join(t.TempDir(), "output"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	spinner = Start(file, "Waiting...")
	if spinner.Enabled() {
		t.Fatal("redirected file enabled terminal animation")
	}
	spinner.Stop()
	info, err := file.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatalf("redirected file changed: %v, %v", info, err)
	}
}
