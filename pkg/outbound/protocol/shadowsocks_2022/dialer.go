package shadowsocks_2022

import (
	"context"
	"crypto/cipher"
	"fmt"
	"net"
	"strings"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

func init() {
	protocol.Register("shadowsocks_2022", NewDialer)
}

type Dialer struct {
	ParentDialer       netproxy.Dialer
	proxyAddress       string
	conf               *ciphers.CipherConf2022
	pskList            [][]byte
	uPSK               []byte
	sg                 shadowsocks.SaltGenerator
	blockCipherEncrypt cipher.Block
	blockCipherDecrypt cipher.Block
}

func NewDialer(parentDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	conf := ciphers.Aead2022CiphersConf[header.Cipher]
	if conf == nil {
		return nil, fmt.Errorf("unsupported shadowsocks_2022 cipher: %s", header.Cipher)
	}
	keyStrList := strings.Split(header.Password, ":")
	pskList := make([][]byte, len(keyStrList))
	for i, keyStr := range keyStrList {
		key, err := ciphers.ValidateBase64PSK(keyStr, conf.KeyLen)
		if err != nil {
			return nil, err
		}
		pskList[i] = key
	}
	uPSK := pskList[len(pskList)-1]
	blockCipherEncrypt, err := conf.NewBlockCipher(pskList[0]) // iPSK0/uPSK
	if err != nil {
		return nil, err
	}
	blockCipherDecrypt, err := conf.NewBlockCipher(uPSK) // uPSK
	if err != nil {
		return nil, err
	}
	sg := shadowsocks.RandomSaltGenerator(conf.SaltLen)
	return &Dialer{
		ParentDialer:       parentDialer,
		proxyAddress:       header.ProxyAddress,
		conf:               conf,
		pskList:            pskList,
		uPSK:               uPSK,
		sg:                 sg,
		blockCipherEncrypt: blockCipherEncrypt,
		blockCipherDecrypt: blockCipherDecrypt,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp":
		addrInfo, err := socks5.AddressFromString(addr)
		if err != nil {
			return nil, err
		}
		// Shadowsocks transfer TCP traffic via TCP tunnel.
		conn, err := d.ParentDialer.DialContext(ctx, network, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		client := NewTCPConn(conn, d.conf, d.pskList, d.uPSK, d.sg, addrInfo)
		if err = protocol.Handshake(ctx, client, func() error { _, err := client.Write(nil); return err }); err != nil {
			return nil, err
		}
		return client, nil

	case "udp":
		conn, err := d.ListenPacket(ctx, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{
			PacketConn: conn,
			Address:    netproxy.NewAddr("udp", addr),
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	// Shadowsocks transfer UDP traffic via UDP tunnel.
	conn, err := d.ParentDialer.DialContext(ctx, "udp", d.proxyAddress)
	if err != nil {
		return nil, err
	}
	return NewUdpConn(conn, d.conf, d.blockCipherEncrypt, d.blockCipherDecrypt, d.pskList, d.uPSK), nil
}
