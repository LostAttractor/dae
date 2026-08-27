package outbound

import (
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

type FixedSelector struct {
	dialerGroup *DialerGroup
}

func NewFixedSelector(dialerGroup *DialerGroup) Selector {
	return &FixedSelector{dialerGroup: dialerGroup}
}

func (s *FixedSelector) fixedDialer() *dialer.Dialer {
	index := s.dialerGroup.selectionPolicy.FixedIndex
	if index < 0 || index >= len(s.dialerGroup.Dialers) {
		return nil
	}
	return s.dialerGroup.Dialers[index]
}

func (s *FixedSelector) Select(networkType *common.NetworkType) *dialer.Dialer {
	d := s.fixedDialer()
	if d == nil || !d.Usable(networkType) {
		return nil
	}
	return d
}

func (s *FixedSelector) SelectedDialer(networkType *common.NetworkType) *dialer.Dialer {
	return s.Select(networkType)
}

func (s *FixedSelector) Refresh(*dialer.Dialer) {}

func (s *FixedSelector) PrintLatencies(networkType *common.NetworkType, logfn func(args ...interface{})) {
	d := s.fixedDialer()
	if d == nil {
		printLatencyHeader(s.dialerGroup, networkType, logfn)
		logfn("  <Index Out Of Range>")
		return
	}
	printDialerLatency(s.dialerGroup, d, networkType, logfn)
}
