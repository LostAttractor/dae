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
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
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

func UnpackDnsMessage(payload []byte, msg *dnsmessage.Msg) error {
	if len(payload) < 12 {
		return fmt.Errorf("%w: DNS header is truncated", ErrBadDnsResponse)
	}
	offset := 12
	questions := int(binary.BigEndian.Uint16(payload[4:6]))
	records := int(binary.BigEndian.Uint16(payload[6:8])) +
		int(binary.BigEndian.Uint16(payload[8:10])) +
		int(binary.BigEndian.Uint16(payload[10:12]))
	for i := 0; i < questions; i++ {
		next, err := skipDnsWireName(payload, offset)
		if err != nil || next+4 > len(payload) {
			return fmt.Errorf("%w: malformed DNS question", ErrBadDnsResponse)
		}
		offset = next + 4
	}
	for i := 0; i < records; i++ {
		next, err := skipDnsWireName(payload, offset)
		if err != nil || next+10 > len(payload) {
			return fmt.Errorf("%w: malformed DNS resource record", ErrBadDnsResponse)
		}
		rdataLength := int(binary.BigEndian.Uint16(payload[next+8 : next+10]))
		offset = next + 10 + rdataLength
		if offset > len(payload) {
			return fmt.Errorf("%w: truncated DNS resource record", ErrBadDnsResponse)
		}
	}
	if offset != len(payload) {
		return fmt.Errorf("%w: %d trailing bytes after DNS message", ErrBadDnsResponse, len(payload)-offset)
	}
	return msg.Unpack(payload)
}

func skipDnsWireName(payload []byte, offset int) (int, error) {
	for {
		if offset >= len(payload) {
			return 0, io.ErrUnexpectedEOF
		}
		length := payload[offset]
		switch length & 0xc0 {
		case 0:
			offset++
			if length == 0 {
				return offset, nil
			}
			if offset+int(length) > len(payload) {
				return 0, io.ErrUnexpectedEOF
			}
			offset += int(length)
		case 0xc0:
			if offset+1 >= len(payload) {
				return 0, io.ErrUnexpectedEOF
			}
			pointer := int(length&0x3f)<<8 | int(payload[offset+1])
			if pointer >= offset {
				return 0, errors.New("DNS compression pointer does not point backward")
			}
			return offset + 2, nil
		default:
			return 0, errors.New("invalid DNS label encoding")
		}
	}
}

// ValidateDnsResponse validates a response against the query sent on the wire.
// Error responses are allowed to omit the question section; restore it so
// response routing can still identify the original lookup.
func ValidateDnsResponse(query, response *dnsmessage.Msg, expectedId uint16) error {
	return validateDnsResponse(query, response, expectedId, false)
}

func ValidateDnsResponseAllowEmptyQuestion(query, response *dnsmessage.Msg, expectedId uint16) error {
	return validateDnsResponse(query, response, expectedId, true)
}

func validateDnsResponse(query, response *dnsmessage.Msg, expectedId uint16, allowEmptyQuestion bool) error {
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
		if !allowEmptyQuestion || response.Rcode == dnsmessage.RcodeSuccess {
			return fmt.Errorf("%w: response has no question", ErrBadDnsResponse)
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

func closeConnAsync(conn net.Conn) {
	if conn != nil {
		go func() { _ = conn.Close() }()
	}
}

func ResolveHttp(ctx context.Context, client *http.Client, endpoint *url.URL, msg *dnsmessage.Msg) error {
	requestID := msg.Id
	query := msg.Copy()
	query.Id = 0
	data, err := query.Pack()
	if err != nil {
		return oops.Wrapf(err, "pack DNS packet")
	}
	if err := CheckDnsMessageSize(len(data)); err != nil {
		return err
	}

	requestURL := *endpoint
	q := requestURL.Query()
	q.Set("dns", base64.RawURLEncoding.EncodeToString(data))
	requestURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("unexpected DoH response status: %v", resp.Status)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/dns-message" {
		return fmt.Errorf("unexpected DoH response content type: %q", resp.Header.Get("Content-Type"))
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, math.MaxUint16+1))
	if err != nil {
		return err
	}
	if err := CheckDnsMessageSize(len(buf)); err != nil {
		return err
	}
	var response dnsmessage.Msg
	if err = UnpackDnsMessage(buf, &response); err != nil {
		return err
	}
	if err = ValidateDnsResponseAllowEmptyQuestion(query, &response, 0); err != nil {
		return err
	}
	if ageValue := resp.Header.Get("Age"); ageValue != "" {
		ageValue, _, _ = strings.Cut(ageValue, ",")
		age, _ := strconv.ParseUint(strings.TrimSpace(ageValue), 10, 64)
		for _, rrs := range [][]dnsmessage.RR{response.Answer, response.Ns, response.Extra} {
			for _, rr := range rrs {
				if rr == nil || rr.Header().Rrtype == dnsmessage.TypeOPT {
					continue
				}
				if uint64(rr.Header().Ttl) <= age {
					rr.Header().Ttl = 0
				} else {
					rr.Header().Ttl -= uint32(age)
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	response.Id = requestID
	*msg = response
	return nil
}

func ResolveStream(stream io.ReadWriter, msg *dnsmessage.Msg) error {
	query := msg.Copy()
	data, err := msg.Pack()
	if err != nil {
		return oops.Wrapf(err, "pack DNS packet")
	}
	if err := CheckDnsMessageSize(len(data)); err != nil {
		return err
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	// DNS over TCP and TLS use a two-byte message length.
	binary.Write(buf, binary.BigEndian, uint16(len(data)))
	buf.Write(data)
	n, err := stream.Write(buf.Bytes())
	if err != nil {
		return oops.Wrapf(err, "failed to write DNS req")
	}
	if n != buf.Len() {
		return oops.Wrapf(io.ErrShortWrite, "failed to write DNS req")
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
	var response dnsmessage.Msg
	if err = UnpackDnsMessage(respBuf, &response); err != nil {
		return err
	}
	if err = ValidateDnsResponseAllowEmptyQuestion(query, &response, query.Id); err != nil {
		return err
	}
	*msg = response
	return nil
}

func ResolveUDP(ctx context.Context, conn net.Conn, msg *dnsmessage.Msg) error {
	return resolveUDP(ctx, conn, msg, consts.DefaultDNSRetryInterval, consts.DefaultDNSTimeout)
}

func resolveUDP(ctx context.Context, conn net.Conn, msg *dnsmessage.Msg, retryInterval, timeout time.Duration) error {
	if err := ctx.Err(); err != nil {
		closeConnAsync(conn)
		return err
	}
	query := msg.Copy()
	data, err := msg.Pack()
	if err != nil {
		return oops.Wrapf(err, "pack DNS packet")
	}
	if err := CheckDnsMessageSize(len(data)); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	success := false
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer func() {
		stopClose()
		if !success {
			closeConnAsync(conn)
		}
	}()
	recvCh := make(chan error, 1)
	var response dnsmessage.Msg
	// The read goroutine owns the buffer and returns it only after Read exits.
	// On cancellation the caller may return before a blocking Close completes.
	respBuf := pool.GetBuffer(consts.MaxDnsMessageSize + 1)
	go func() {
		defer pool.PutBuffer(respBuf)
		for {
			n, err := conn.Read(respBuf)
			if err != nil {
				recvCh <- err
				return
			}
			if n > consts.MaxDnsMessageSize {
				continue
			}
			var resp dnsmessage.Msg
			if err := UnpackDnsMessage(respBuf[:n], &resp); err != nil {
				continue
			}
			if err := ValidateDnsResponse(query, &resp, query.Id); err != nil {
				continue
			}
			response = resp
			recvCh <- nil
			return
		}
	}()
	commitResult := func(err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		*msg = response
		success = true
		return nil
	}
	pollResult := func() (bool, error) {
		select {
		case err := <-recvCh:
			return true, commitResult(err)
		default:
			return false, nil
		}
	}
	attempts := consts.DefaultDNSRetryCount
	if msg.Opcode != dnsmessage.OpcodeQuery && msg.Opcode != dnsmessage.OpcodeNotify {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := conn.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// A previous retry may already have produced a valid response.
			// Commit it instead of losing it to a later write failure.
			if received, resultErr := pollResult(); received {
				return resultErr
			}
			return err
		}
		// Prefer an already validated response over a retry timer that is also ready.
		if received, err := pollResult(); received {
			return err
		}

		wait := retryInterval
		if attempts == 1 {
			wait = timeout
		}
		select {
		case err := <-recvCh:
			return commitResult(err)
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
			// The response send may have raced with timer delivery.
			if received, err := pollResult(); received {
				return err
			}
		}
	}
	// Give a response concurrent with the final timer one last chance to win.
	if received, err := pollResult(); received {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return fmt.Errorf("DNS query timed out after %d attempts: %w", attempts, context.DeadlineExceeded)
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
	var msg dnsmessage.Msg
	msg.SetQuestion(dnsmessage.CanonicalName(host), typ)

	conn, err := dialer.DialContext(ctx, network, server.String())
	if err != nil {
		return nil, err
	}
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { closeConnAsync(conn) }) }
	defer closeConn()
	stopClose := context.AfterFunc(ctx, closeConn)
	defer stopClose()

	result := make(chan error, 1)
	request := msg.Copy()
	go func() {
		if network == "tcp" {
			result <- ResolveStream(conn, request)
		} else {
			result <- ResolveUDP(ctx, conn, request)
		}
	}()
	select {
	case err = <-result:
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if err != nil {
			return nil, err
		}
		msg = *request
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return msg.Answer, nil
}
