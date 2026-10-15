package vision

import (
	"bytes"
	"encoding/binary"
)

var tls13SupportedVersions = []byte{0, 43, 0, 2, 3, 4}

// Detection only enables the direct optimization when a supported TLS 1.3
// ServerHello was observed. Undecidable/fragmented traffic remains encapsulated.
func (c *Conn) filterTLS(p []byte) (bool, bool, int) {
	c.filterMu.Lock()
	defer c.filterMu.Unlock()
	if len(p) == 0 || c.packetsToFilter <= 0 {
		return c.isTLS, c.enableXTLS, c.packetsToFilter
	}
	c.packetsToFilter--
	index := bytes.Index(p, []byte{22, 3, 3})
	if index >= 0 && len(p) >= index+6 && p[index+5] == 2 {
		c.isTLS = true
		c.remainingServerHello = binary.BigEndian.Uint16(p[index+3:]) + 5
		if len(p) > index+43 {
			sid := int(p[index+43])
			if len(p) >= index+46+sid {
				c.cipher = binary.BigEndian.Uint16(p[index+44+sid:])
			}
		}
	} else if i := bytes.Index(p, []byte{22, 3}); i >= 0 && len(p) >= i+6 && p[i+5] == 1 {
		c.isTLS = true
	}
	if c.remainingServerHello > 0 {
		start := max(0, index)
		size := min(int(c.remainingServerHello), len(p)-start)
		if bytes.Contains(p[start:start+size], tls13SupportedVersions) && c.cipher >= 0x1301 && c.cipher <= 0x1304 {
			c.enableXTLS = true
			c.packetsToFilter = 0
		}
		c.remainingServerHello -= uint16(size)
		if c.remainingServerHello == 0 {
			c.packetsToFilter = 0
		}
	}
	return c.isTLS, c.enableXTLS, c.packetsToFilter
}
