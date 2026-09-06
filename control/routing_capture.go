// SPDX-License-Identifier: AGPL-3.0-only

package control

// API bypass rules must terminate before either HTTP or destination capture.
// TCP capture permits hostname sniffing without observing DNS requests.
type routingCapture struct {
	before int
	tcp    bool
}
