// SPDX-License-Identifier: AGPL-3.0-only

package transport

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common/netutils"
	dnsmessage "github.com/miekg/dns"
)

func ResolveHttp(ctx context.Context, client *http.Client, endpoint *url.URL, msg *dnsmessage.Msg) error {
	requestID := msg.Id
	query := msg.Copy()
	query.Id = 0
	data, err := query.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	if err := netutils.CheckDnsMessageSize(len(data)); err != nil {
		return err
	}
	requestURL := endpoint.Clone()
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
	if err := netutils.CheckDnsMessageSize(len(buf)); err != nil {
		return err
	}
	var response dnsmessage.Msg
	if err = netutils.UnpackDnsMessage(buf, &response); err != nil {
		return err
	}
	if err = netutils.ValidateDnsResponseAllowEmptyQuestion(query, &response, 0); err != nil {
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
