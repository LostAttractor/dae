// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"reflect"

	"github.com/daeuniverse/dae/common"
)

// ControlPlaneConfig projects fields owned by the control plane. Services can
// be reconfigured in place; startup preferences affect only the next startup.
// Protocol-specific invariants remain with the runtime that owns the resource.
func (g Global) ControlPlaneConfig() Global {
	g.SoMarkFromDae = common.EffectiveSoMarkFromDae(g.SoMarkFromDae)
	v := reflect.ValueOf(&g).Elem()
	for i := range v.NumField() {
		switch v.Type().Field(i).Tag.Get("reload") {
		case "services", "startup":
			v.Field(i).SetZero()
		}
	}
	return g
}

// CheckReload rejects daemon settings that require restarting process services.
func (g Global) CheckReload(next Global) error {
	before, after := reflect.ValueOf(g), reflect.ValueOf(next)
	for i := range before.NumField() {
		field := before.Type().Field(i)
		if field.Tag.Get("reload") == "restart" && !reflect.DeepEqual(before.Field(i).Interface(), after.Field(i).Interface()) {
			return fmt.Errorf("%s (%v -> %v) cannot be changed by reload; restart dae to apply it", field.Tag.Get("mapstructure"), before.Field(i).Interface(), after.Field(i).Interface())
		}
	}
	return nil
}
