// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
)

func diagnosticNetworkIndex(proto consts.L4ProtoType, family consts.IpVersionType) common.NetworkIndex {
	network := common.NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: family.ToIpVersionStr()}
	if proto&consts.L4ProtoType_UDP != 0 {
		network.L4Proto = consts.L4ProtoStr_UDP
	}
	return network.Index()
}
