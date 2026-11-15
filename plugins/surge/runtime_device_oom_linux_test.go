//go:build linux && surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/plugins/surge/internal/processgroup"
)

func TestRuntimeDeviceOOMMigrationAndRecovery(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{MemoryLimit: 16 << 20, NodeWorkers: 1, Timeout: 10 * time.Second})
	to, other := [6]byte{2, 0, 0, 0, 0, 2}, [6]byte{2, 0, 0, 0, 0, 3}
	if !r.data.write(t.Context(), testMACScope(other), "cookie", "other", false) || !r.data.write(t.Context(), testLocalScope, "cookie", "local", false) {
		t.Fatal("seed unrelated scopes")
	}
	result, err := r.Run(t.Context(), `
if (!$persistentStore.write("captured", "cookie")) throw Error("store write failed");
const retained=[];
for (let i=0; i<32; i++) {
  const bytes=new Uint8Array(8*1024*1024);
  bytes.fill(1);
  retained.push(bytes);
}`, Invocation{Scope: testDeviceScope})
	result.Close()
	if !errors.Is(err, processgroup.ErrOOMKilled) || !errors.Is(err, io.EOF) {
		t.Fatalf("device OOM lost its error chain: %v", err)
	}
	if len(r.data.active) != 0 {
		t.Fatalf("OOM retained device execution: %v", r.data.active)
	}
	status := r.backend.status().NodeJS
	if status.Active != 0 || status.Idle != 0 || status.Started != 1 || status.Discarded != 1 || status.CgroupOOMKills == 0 {
		t.Fatalf("OOM worker was not retired/accounted: %+v", status)
	}
	if moved, err := r.data.migrate(t.Context(), testDeviceMAC, to); err != nil || moved != 1 {
		t.Fatalf("OOM left the source bucket busy or lost its write: moved=%d err=%v", moved, err)
	}
	for _, test := range []struct {
		scope ScriptScope
		want  string
	}{
		{testMACScope(to), `"captured"`},
		{testDeviceScope, `null`},
		{testMACScope(other), `"other"`},
		{testLocalScope, `"local"`},
	} {
		result, err := r.Run(t.Context(), fmt.Sprintf(`
if ($persistentStore.read("cookie") !== %s) throw Error("wrong scope state");
$done();`, test.want), Invocation{Scope: test.scope})
		result.Close()
		if err != nil {
			t.Fatalf("replacement worker scope=%+v: %v", test.scope, err)
		}
	}
	status = r.backend.status().NodeJS
	if status.Active != 0 || status.Idle != 1 || status.Limit != 1 || status.Started != 2 || status.Reused != 3 || status.Discarded != 1 || status.CgroupOOMKills == 0 {
		t.Fatalf("device scopes did not share the recovered worker pool: %+v", status)
	}
	if len(r.data.active) != 0 {
		t.Fatalf("recovery retained device executions: %v", r.data.active)
	}
}
