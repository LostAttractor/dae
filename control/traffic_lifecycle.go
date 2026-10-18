// SPDX-License-Identifier: AGPL-3.0-only

package control

import "context"

func newPlaneTraffic(parent context.Context, connections *tcpConnectionSet, endpoints *UdpEndpointPool) planeTraffic {
	ctx, cancel := context.WithCancel(parent)
	return planeTraffic{
		tcpConnections:  &tcpConnectionTracker{connections: connections},
		udpTaskPool:     newUdpTaskPool(udpPacketWork.execute),
		udpEndpoints:    endpoints,
		tcpSetupCtx:     ctx,
		cancelTCPSetups: cancel,
	}
}

func (c *planeTraffic) interruptSetups() {
	c.abortConnections.Store(true)
	// Stop this generation's admission before aborting Runtime-owned sockets.
	c.tcpConnections.abort()
	c.cancelTCPSetups()
	c.udpTaskPool.cancel()
}

func (c *planeTraffic) stopSetups() {
	c.udpDraining.Store(true)
	c.tcpConnections.stopAccepting()
	c.cancelTCPSetups()
	c.udpTaskPool.close()
	c.tcpConnections.waitForSetups()
}
