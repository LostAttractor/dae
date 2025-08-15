package outbound

import (
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	log "github.com/sirupsen/logrus"
)

type Selector interface {
	Select(networkType *common.NetworkType) (dialer *dialer.Dialer)
	NotifyStatusChange(dialer *dialer.Dialer)
	PrintLatencies(networkType *common.NetworkType, level log.Level)
}

type BaseSelector struct {
	dialerGroup         *DialerGroup
	aliveChangeCallback func(alive bool, networkType *common.NetworkType)
	networkIndexToAlive [4]*bool
}

func (s *BaseSelector) handleAliveStateChange(alive bool, networkType *common.NetworkType) {
	index := common.NetworkTypeToIndex(networkType)
	if s.networkIndexToAlive[index] != nil && *s.networkIndexToAlive[index] == alive {
		return
	}

	if alive {
		log.WithFields(log.Fields{
			"group":   s.dialerGroup.Name,
			"network": networkType.String(),
		}).Infof("Group is alive")
	} else {
		log.WithFields(log.Fields{
			"group":   s.dialerGroup.Name,
			"network": networkType.String(),
		}).Infof("Group has no dialer alive")
	}
	s.networkIndexToAlive[index] = &alive
	s.aliveChangeCallback(alive, networkType)
}
