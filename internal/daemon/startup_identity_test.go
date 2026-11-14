// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"golang.org/x/sys/unix"
)

func TestRestoredProcessNameRoutesInternalRequests(t *testing.T) {
	name, child := os.LookupEnv("DAE_TEST_PROCESS_NAME")
	if !child {
		for _, name := range []string{"dae-name-test", " dae name ", "   "} {
			t.Run(name, func(t *testing.T) {
				command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRestoredProcessNameRoutesInternalRequests$")
				command.Env = append(os.Environ(), "DAE_TEST_PROCESS_NAME="+name)
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("restore %q: %v\n%s", name, err, output)
				}
			})
		}
		return
	}

	// Exercise restoration from a non-leader thread, as Go startup may do.
	runtime.LockOSThread()
	result := make(chan error, 1)
	if unix.Gettid() == os.Getpid() {
		go func() { result <- restoreProcessName(name) }()
	} else {
		result <- restoreProcessName(name)
	}
	err := <-result
	runtime.UnlockOSThread()
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", strings.Repeat("x", 16), "dae\x00other"} {
		if err := restoreProcessName(invalid); err == nil {
			t.Fatalf("accepted invalid process name %q", invalid)
		}
	}
	if got := control.CurrentProcessIdentity(); got.Name != name || got.PID != uint32(os.Getpid()) {
		t.Fatalf("restored identity: pid=%d name=%q, want pid=%d name=%q", got.PID, got.Name, os.Getpid(), name)
	}

	sections, err := config_parser.Parse("global {}\nrouting { pname('" + name + "') -> block\nfallback: direct }")
	if err != nil {
		t.Fatal(err)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatal(err)
	}
	conf.Global.SoMarkFromDae = 0
	rules, err := control.PrepareRules(t.Context(), &conf.Routing, nil)
	if err != nil {
		t.Fatal(err)
	}
	plane, err := control.NewUserspaceControlPlane(t.Context(), control.UserspaceResources{SkipConnectivityWait: true}, rules, nil, conf, nil,
		func(*http.Client) (control.PreparedMITM, error) { return control.PreparedMITM{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer plane.Close()
	conn, err := plane.DNSResolverDialer()(t.Context(), "udp", netip.MustParseAddrPort("127.0.0.1:53"))
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "blocked by routing") {
		t.Fatalf("internal DNS ignored the restored pname rule: %v", err)
	}
	client, closeClient := plane.NewPreparationClient()
	defer closeClient()
	response, err := client.Get("http://127.0.0.1:1/resource")
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "blocked by routing") {
		t.Fatalf("resource request ignored the restored pname rule: %v", err)
	}
}
