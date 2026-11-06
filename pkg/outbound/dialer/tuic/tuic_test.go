package tuic

import (
	"reflect"
	"strings"
	"testing"
)

func TestReduceRttLinkRoundTrip(t *testing.T) {
	for link, want := range map[string]bool{
		"tuic://uuid:password@example.com:443?reduce_rtt=1#node":            true,
		"tuic://uuid:password@example.com:443?zero_rtt_handshake=true#node": true,
		"tuic://uuid:password@example.com:443?reduce_rtt=0#node":            false,
		"tuic://uuid:password@example.com:443?alpn=h3#node":                 false,
	} {
		s, err := ParseTuicURL(link)
		if err != nil {
			t.Fatal(err)
		}
		exported := s.ExportToURL()
		again, err := ParseTuicURL(exported)
		if err != nil {
			t.Fatal(err)
		}
		if s.ReduceRtt != want || strings.Contains(exported, "reduce_rtt=1") != want || !reflect.DeepEqual(s, again) {
			t.Errorf("%s: reduce_rtt=%v, exported %s as %+v", link, s.ReduceRtt, exported, again)
		}
	}
}
