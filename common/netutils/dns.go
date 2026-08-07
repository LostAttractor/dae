/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/samber/oops"
)

var (
	ErrBadDnsAns      = errors.New("bad dns answer")
	ErrBadDnsResponse = errors.New("bad dns response")
)

func CheckDnsMessageSize(size int) error {
	if size > math.MaxUint16 {
		return fmt.Errorf("DNS message exceeds 65535-byte limit: %d", size)
	}
	return nil
}

// ValidateDnsResponse validates a response against the query sent on the wire.
// Error responses are allowed to omit the question section; restore it so
// response routing can still identify the original lookup.
func ValidateDnsResponse(query, response *dnsmessage.Msg, expectedId uint16) error {
	if !response.Response {
		return fmt.Errorf("%w: QR bit is not set", ErrBadDnsResponse)
	}
	if response.Id != expectedId {
		return fmt.Errorf("%w: transaction ID %d, want %d", ErrBadDnsResponse, response.Id, expectedId)
	}
	if response.Opcode != query.Opcode {
		return fmt.Errorf("%w: opcode %d, want %d", ErrBadDnsResponse, response.Opcode, query.Opcode)
	}
	if len(response.Question) == 0 {
		if response.Rcode == dnsmessage.RcodeSuccess {
			return fmt.Errorf("%w: successful response has no question", ErrBadDnsResponse)
		}
		response.Question = append([]dnsmessage.Question(nil), query.Question...)
		return nil
	}
	if len(response.Question) != len(query.Question) {
		return fmt.Errorf("%w: question count %d, want %d", ErrBadDnsResponse, len(response.Question), len(query.Question))
	}
	for i := range query.Question {
		got, want := response.Question[i], query.Question[i]
		if dnsmessage.CanonicalName(got.Name) != dnsmessage.CanonicalName(want.Name) ||
			got.Qtype != want.Qtype || got.Qclass != want.Qclass {
			return fmt.Errorf("%w: question %v, want %v", ErrBadDnsResponse, got, want)
		}
	}
	return nil
}

func ResolveHttp(client *http.Client, url *url.URL, msg *dnsmessage.Msg) error {
	data, err := msg.Pack()
	if err != nil {
		return oops.Wrapf(err, "pack DNS packet")
	}

	// According https://datatracker.ietf.org/doc/html/rfc8484#section-4
	// msg id should set to 0 when transport over HTTPS for cache friendly.
	binary.BigEndian.PutUint16(data[0:2], 0)

	q := url.Query()
	q.Set("dns", base64.RawURLEncoding.EncodeToString(data))
	url.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, url.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Host = url.Host
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected DoH response status: %v", resp.Status)
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err = msg.Unpack(buf); err != nil {
		return err
	}
	return nil
}

func ResolveStream(stream io.ReadWriter, msg *dnsmessage.Msg, quic bool) error {
	data, err := msg.Pack()
	if err != nil {
		return oops.Wrapf(err, "pack DNS packet")
	}
	if len(data) > math.MaxUint16 {
		return fmt.Errorf("DNS message exceeds stream size limit: %d", len(data))
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if quic {
		// According https://datatracker.ietf.org/doc/html/rfc9250#section-4.2.1
		// msg id should set to 0 when transport over QUIC.
		// thanks https://github.com/natesales/q/blob/1cb2639caf69bd0a9b46494a3c689130df8fb24a/transport/quic.go#L97
		binary.BigEndian.PutUint16(data[0:2], 0)
	}
	// DNS over TCP, TLS and QUIC all use a two-byte message length.
	binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)
	n, err := stream.Write(buf.Bytes())
	if err != nil {
		return oops.Wrapf(err, "failed to write DNS req")
	}
	if n != buf.Len() {
		return oops.Wrapf(io.ErrShortWrite, "failed to write DNS req")
	}

	if quic {
		// RFC 9250 section 4.2 requires the query to be followed by STREAM FIN.
		if c, ok := stream.(interface{ Close() error }); ok {
			// Half-close the send side so the server knows the query is complete.
			_ = c.Close()
		}
	}

	lenBuf := pool.GetBuffer(2)
	defer pool.PutBuffer(lenBuf)
	// Read two byte length.
	if _, err = io.ReadFull(stream, lenBuf); err != nil {
		return oops.Wrapf(err, "failed to read DNS resp payload length")
	}
	respBuf := pool.GetBuffer(int(binary.BigEndian.Uint16(lenBuf)))
	defer pool.PutBuffer(respBuf)
	if _, err = io.ReadFull(stream, respBuf); err != nil {
		return oops.Wrapf(err, "failed to read DNS resp payload")
	}
	if err = msg.Unpack(respBuf); err != nil {
		return err
	}
	if quic {
		if msg.Id != 0 {
			return fmt.Errorf("DoQ response has non-zero DNS message ID: %d", msg.Id)
		}
		// Ordinary queries have one response. Wait for the required server FIN
		// and reject a second framed message or trailing bytes.
		extra, err := io.ReadAll(io.LimitReader(stream, 1))
		if err != nil {
			return oops.Wrapf(err, "failed to read DoQ stream FIN")
		}
		if len(extra) != 0 {
			return fmt.Errorf("unexpected trailing data after DoQ response")
		}
	}
	return nil
}

func ResolveUDP(conn net.Conn, msg *dnsmessage.Msg) error {
	data, err := msg.Pack()
	if err != nil {
		return oops.Wrapf(err, "pack DNS packet")
	}

	// TODO: SetReadDeadline 无法生效的情况下, 这里就会stuck
	// TODO: SetDeadline 可能会不被支持, 特别是 SetWriteDeadline
	conn.SetDeadline(time.Now().Add(consts.DefaultDNSTimeout))
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	sendCh := make(chan error, 1)
	recvCh := make(chan error, 1)
	go func() {
		for i := 0; i < consts.DefaultDNSRetryCount; i++ {
			_, err := conn.Write(data)
			if err != nil {
				sendCh <- err
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(consts.DefaultDNSRetryInterval):
			}
		}
	}()

	respBuf := pool.GetBuffer(consts.EthernetMtu)
	defer pool.PutBuffer(respBuf)
	var n int
	go func() {
		// Wait for response.
		n, err = conn.Read(respBuf)
		recvCh <- err
	}()

	select {
	case err := <-sendCh:
		return err
	case err := <-recvCh:
		if err != nil {
			return err
		}
	}

	return msg.Unpack(respBuf[:n])
}

func ResolveNetip(d netproxy.Dialer, dns netip.AddrPort, host string, typ uint16, network string) (addrs []netip.Addr, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), consts.DefaultDialTimeout)
	defer cancel()
	return ResolveNetipContext(ctx, d, dns, host, typ, network)
}

// ResolveNetipContext is ResolveNetip with caller-controlled cancellation.
// Canceling ctx also closes an established DNS connection, so a health-check
// goroutine cannot remain stuck in a TCP/UDP read while its dialer is closing.
func ResolveNetipContext(ctx context.Context, d netproxy.Dialer, dns netip.AddrPort, host string, typ uint16, network string) (addrs []netip.Addr, err error) {
	resources, err := resolveContext(ctx, d, dns, host, typ, network)
	if err != nil {
		return nil, err
	}
	for _, ans := range resources {
		if ans.Header().Rrtype != typ {
			continue
		}
		var (
			ip  netip.Addr
			okk bool
		)
		switch typ {
		case dnsmessage.TypeA:
			a, ok := ans.(*dnsmessage.A)
			if !ok {
				return nil, ErrBadDnsAns
			}
			ip, okk = netip.AddrFromSlice(a.A)
		case dnsmessage.TypeAAAA:
			a, ok := ans.(*dnsmessage.AAAA)
			if !ok {
				return nil, ErrBadDnsAns
			}
			ip, okk = netip.AddrFromSlice(a.AAAA)
		}
		if !okk {
			continue
		}
		addrs = append(addrs, ip)
	}
	return addrs, nil
}

func ResolveNS(d netproxy.Dialer, dns netip.AddrPort, host string, network string) (records []string, err error) {
	typ := dnsmessage.TypeNS
	resources, err := resolve(d, dns, host, typ, network)
	if err != nil {
		return nil, err
	}
	for _, ans := range resources {
		if ans.Header().Rrtype != typ {
			continue
		}
		ns, ok := ans.(*dnsmessage.NS)
		if !ok {
			return nil, ErrBadDnsAns
		}
		records = append(records, ns.Ns)
	}
	return records, nil
}

func ResolveSOA(d netproxy.Dialer, dns netip.AddrPort, host string, network string) (records []string, err error) {
	typ := dnsmessage.TypeSOA
	resources, err := resolve(d, dns, host, typ, network)
	if err != nil {
		return nil, err
	}
	for _, ans := range resources {
		if ans.Header().Rrtype != typ {
			continue
		}
		ns, ok := ans.(*dnsmessage.SOA)
		if !ok {
			return nil, ErrBadDnsAns
		}
		records = append(records, ns.Ns)
	}
	return records, nil
}

func resolve(dialer netproxy.Dialer, server netip.AddrPort, host string, typ uint16, network string) (ans []dnsmessage.RR, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), consts.DefaultDialTimeout)
	defer cancel()
	return resolveContext(ctx, dialer, server, host, typ, network)
}

func resolveContext(ctx context.Context, dialer netproxy.Dialer, server netip.AddrPort, host string, typ uint16, network string) (ans []dnsmessage.RR, err error) {
	// Build DNS req.
	msg := dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:               uint16(fastrand.Intn(math.MaxUint16 + 1)),
			Response:         false,
			Opcode:           0,
			Truncated:        false,
			RecursionDesired: true,
			Authoritative:    false,
		},
	}
	msg.SetQuestion(dnsmessage.CanonicalName(host), typ)

	conn, err := dialer.DialContext(ctx, network, server.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()

	if network == "tcp" {
		err = ResolveStream(conn, &msg, false)
	} else {
		err = ResolveUDP(conn, &msg)
	}
	if err != nil {
		return nil, err
	}
	return msg.Answer, nil
}
