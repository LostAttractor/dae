package client

import (
	"context"
	"crypto/tls"
	"errors"
	"math"
	"net"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/pmtud"
	"github.com/daeuniverse/quic-go"
)

const (
	defaultStreamReceiveWindow = 8388608                            // 8MB
	defaultConnReceiveWindow   = defaultStreamReceiveWindow * 5 / 2 // 20MB
	defaultMaxIdleTimeout      = 30 * time.Second
	defaultKeepAlivePeriod     = 10 * time.Second
)

type Config struct {
	Addr            net.Addr
	ResolveAddr     func(context.Context) (net.Addr, error)
	NextDialer      netproxy.Dialer
	Auth            string
	TLSConfig       tls.Config
	QUICConfig      quic.Config
	BandwidthConfig BandwidthConfig
	UDPHopInterval  time.Duration
	FastOpen        bool

	filled bool // whether the fields have been verified and filled
}

// verifyAndFill fills the fields that are not set by the user with default values when possible,
// and returns an error if the user has not set a required field or has set an invalid value.
func (c *Config) verifyAndFill() error {
	if c.filled {
		return nil
	}
	if c.NextDialer == nil {
		return errors.New("Hysteria2 config: NextDialer must be set")
	}
	if c.BandwidthConfig.MaxTx > math.MaxInt64 || c.BandwidthConfig.MaxRx > math.MaxInt64 {
		return errors.New("Hysteria2 bandwidth must not exceed MaxInt64 bytes per second")
	}
	if c.QUICConfig.InitialStreamReceiveWindow == 0 {
		c.QUICConfig.InitialStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.InitialStreamReceiveWindow < 16384 {
		return errors.New("Hysteria2 config: QUICConfig.InitialStreamReceiveWindow must be at least 16384")
	}
	if c.QUICConfig.MaxStreamReceiveWindow == 0 {
		c.QUICConfig.MaxStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.MaxStreamReceiveWindow < 16384 {
		return errors.New("Hysteria2 config: QUICConfig.MaxStreamReceiveWindow must be at least 16384")
	}
	if c.QUICConfig.InitialConnectionReceiveWindow == 0 {
		c.QUICConfig.InitialConnectionReceiveWindow = defaultConnReceiveWindow
	} else if c.QUICConfig.InitialConnectionReceiveWindow < 16384 {
		return errors.New("Hysteria2 config: QUICConfig.InitialConnectionReceiveWindow must be at least 16384")
	}
	if c.QUICConfig.MaxConnectionReceiveWindow == 0 {
		c.QUICConfig.MaxConnectionReceiveWindow = defaultConnReceiveWindow
	} else if c.QUICConfig.MaxConnectionReceiveWindow < 16384 {
		return errors.New("Hysteria2 config: QUICConfig.MaxConnectionReceiveWindow must be at least 16384")
	}
	if c.QUICConfig.MaxIdleTimeout == 0 {
		c.QUICConfig.MaxIdleTimeout = defaultMaxIdleTimeout
	} else if c.QUICConfig.MaxIdleTimeout < 4*time.Second || c.QUICConfig.MaxIdleTimeout > 120*time.Second {
		return errors.New("Hysteria2 config: QUICConfig.MaxIdleTimeout must be between 4s and 120s")
	}
	if c.QUICConfig.KeepAlivePeriod == 0 {
		c.QUICConfig.KeepAlivePeriod = defaultKeepAlivePeriod
	} else if c.QUICConfig.KeepAlivePeriod < 2*time.Second || c.QUICConfig.KeepAlivePeriod > 60*time.Second {
		return errors.New("Hysteria2 config: QUICConfig.KeepAlivePeriod must be between 2s and 60s")
	}
	c.QUICConfig.DisablePathMTUDiscovery = c.QUICConfig.DisablePathMTUDiscovery || pmtud.DisablePathMTUDiscovery
	c.QUICConfig.EnableDatagrams = true

	c.filled = true
	return nil
}

// BandwidthConfig describes the maximum bandwidth that the server can use, in bytes per second.
type BandwidthConfig struct {
	MaxTx uint64
	MaxRx uint64
}
