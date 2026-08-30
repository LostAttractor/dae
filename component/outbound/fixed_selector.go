package outbound

import (
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

type fixedSelector struct {
	dialerGroup *DialerGroup
}

func (s *fixedSelector) fixedDialer() *dialer.Dialer {
	index := s.dialerGroup.selectionPolicy.FixedIndex
	if index < 0 || index >= len(s.dialerGroup.Dialers) {
		return nil
	}
	return s.dialerGroup.Dialers[index]
}

func (s *fixedSelector) Select(networkType *common.NetworkType) *dialer.Dialer {
	d := s.fixedDialer()
	if d == nil || !d.Usable(networkType) {
		return nil
	}
	return d
}

func (s *fixedSelector) SelectedDialer(networkType *common.NetworkType) *dialer.Dialer {
	return s.Select(networkType)
}

func (s *fixedSelector) Refresh(*dialer.Dialer) {}

func (s *fixedSelector) EnableTolerance() {}
