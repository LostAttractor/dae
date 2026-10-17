// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

func TestDNSRaceRejectsUncorrelatedAndEmptyResponses(t *testing.T) {
	request := &DNSExchange{DNSPacket: DNSMessage(new(dns.Msg).SetQuestion("race.example.", dns.TypeA))}
	response, err := RaceDNSServers(t.Context(), request, []string{"wrong", "empty", "valid"}, func(_ context.Context, query *DNSExchange, server string) (*DNSResponse, error) {
		if !query.Independent() || query == request {
			t.Error("race shared the parent transport lifetime")
		}
		if server == "empty" {
			return nil, nil
		}
		message := new(dns.Msg).SetReply(query.MessageCopy())
		if server == "wrong" {
			message.Id++
		} else {
			message.Rcode = dns.RcodeNameError
		}
		return &DNSResponse{DNSPacket: DNSMessage(message)}, nil
	})
	if err != nil || response == nil || response.MessageCopy().Rcode != dns.RcodeNameError {
		t.Fatalf("invalid success outranked a valid negative answer: %v, %v", response, err)
	}
}
