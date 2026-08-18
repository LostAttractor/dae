package outbound

import (
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	log "github.com/sirupsen/logrus"
)

type Selector interface {
	InitializeConnectivity()
	Select(networkType *common.NetworkType) (dialer *dialer.Dialer)
	SelectedDialer(networkType *common.NetworkType) (dialer *dialer.Dialer)
	NotifyStatusChange(dialer *dialer.Dialer)
	PrintLatencies(networkType *common.NetworkType, logfn func(args ...interface{}))
}

func (s *BaseSelector) InitializeConnectivity() {
	for i := 0; i < 4; i++ {
		s.handleAliveStateChange(false, common.IndexToNetworkType(i))
	}
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
	stats.RecordGroup(s.dialerGroup.Name, index, alive)
	s.aliveChangeCallback(alive, networkType)
}

func isDialerAlive(d *dialer.Dialer, networkType *common.NetworkType) bool {
	alive, support := d.SelectionState(networkType)
	return alive && support == dialer.NetworkSupportConfirmed
}

func preferredAliveDialers(dialers []*dialer.Dialer, networkType *common.NetworkType) []*dialer.Dialer {
	confirmed := make([]*dialer.Dialer, 0, len(dialers))
	for _, d := range dialers {
		if isDialerAlive(d, networkType) {
			confirmed = append(confirmed, d)
		}
	}
	return confirmed
}
