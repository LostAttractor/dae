// SPDX-License-Identifier: AGPL-3.0-only
package config

import (
	"github.com/daeuniverse/dae/pkg/config_parser"
	"reflect"
)

type sectionCodec struct {
	parse   func(reflect.Value, *config_parser.Section) error
	marshal func(*Marshaller, reflect.Value, int) error
}

func codecFor[T any](parse func(*T, *config_parser.Section) error, marshal func(*Marshaller, T, int) error) sectionCodec {
	return sectionCodec{
		parse: func(to reflect.Value, section *config_parser.Section) error {
			return parse(to.Interface().(*T), section)
		},
		marshal: func(m *Marshaller, from reflect.Value, depth int) error {
			return marshal(m, from.Interface().(T), depth)
		},
	}
}

var sectionCodecs map[reflect.Type]sectionCodec

func init() {
	sectionCodecs = map[reflect.Type]sectionCodec{
		reflect.TypeFor[MITM]():           codecFor(parseMITM, (*Marshaller).marshalMITM),
		reflect.TypeFor[Plugins]():        codecFor(parsePlugins, (*Marshaller).marshalPlugins),
		reflect.TypeFor[[]Node]():         codecFor(parseNodeList, (*Marshaller).marshalNodes),
		reflect.TypeFor[[]Subscription](): codecFor(parseSubscriptionList, (*Marshaller).marshalSubscriptions),
		reflect.TypeFor[Routing]():        codecFor(parseRouting, (*Marshaller).marshalRouting),
	}

}
