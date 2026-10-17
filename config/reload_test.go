// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"reflect"
	"testing"
)

func TestGlobalFieldsDeclareReloadOwnership(t *testing.T) {
	typ := reflect.TypeFor[Global]()
	for i := range typ.NumField() {
		field := typ.Field(i)
		switch field.Tag.Get("reload") {
		case "plane", "services", "startup", "restart":
		default:
			t.Errorf("Global.%s must declare its reload owner", field.Name)
		}
	}
}

func TestReloadSeparatesServicesFromControlPlane(t *testing.T) {
	before := Global{TproxyPort: 12345}
	after := before
	after.APIKey, after.LogLevel, after.PprofPort, after.MetricsPort = "new", "debug", 8081, 8082
	after.DisableWaitingNetwork, after.ResourceCache = true, true
	after.ResourceUpdateInterval = 123
	after.SoMarkFromDae = 0x100
	if !reflect.DeepEqual(before.ControlPlaneConfig(), after.ControlPlaneConfig()) || before.CheckReload(after) != nil {
		t.Fatal("service-only changes rebuilt routing or required restart")
	}
	after.DNSResolver = "192.0.2.53"
	if reflect.DeepEqual(before.ControlPlaneConfig(), after.ControlPlaneConfig()) {
		t.Fatal("resolver changes did not rebuild outbound clients")
	}
	after.TproxyPort++
	if before.CheckReload(after) == nil {
		t.Fatal("changing the process listener port did not require restart")
	}
}
