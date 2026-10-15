package protocol

import (
	"fmt"
	"strconv"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type Creator func(parentDialer netproxy.Dialer, header Header) (netproxy.Dialer, error)
type LayerCreator func(parentDialer netproxy.Dialer, header Header) (netproxy.Layer, error)

var Mapper = make(map[string]LayerCreator)

func Register(name string, c Creator) {
	Mapper[name] = func(parentDialer netproxy.Dialer, header Header) (netproxy.Layer, error) {
		dialer, err := c(parentDialer, header)
		if err != nil {
			return netproxy.Layer{}, err
		}
		return netproxy.Layer{Data: dialer}, nil
	}
}

func RegisterLayer(name string, c LayerCreator) { Mapper[name] = c }

func Build(name string, parentDialer netproxy.Dialer, header Header) (netproxy.Layer, error) {
	creator, ok := Mapper[name]
	if !ok {
		return netproxy.Layer{}, fmt.Errorf("no conn creator registered for %v", strconv.Quote(name))
	}
	return creator(parentDialer, header)
}
