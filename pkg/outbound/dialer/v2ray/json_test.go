package v2ray

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"reflect"
	"testing"
)

func jsonVMessLink(payload string) string {
	return "vmess://" + base64.RawStdEncoding.EncodeToString([]byte(payload))
}

func TestVMessJSONSubscriptionCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, payload string
		port, aid, ps string
		insecure      bool
	}{
		{"numeric", `{"v":2,"port":443,"aid":0,"ps":123,"allowInsecure":1}`, "443", "0", "123", true},
		{"strings", `{"v":"2","port":"443","aid":"0","ps":"<节点>&","allowInsecure":"1"}`, "443", "0", "<节点>&", true},
		{"null", `{"port":null,"aid":null,"ps":null,"allowInsecure":null}`, "", "0", "", false},
		{"number spelling", `{"port":4.43e2,"aid":0.0,"ps":-2.5}`, "4.43e2", "0.0", "-2.5", false},
		{"case insensitive", `{"PORT":443,"ALLOWINSECURE":true}`, "443", "0", "", true},
		{"last duplicate wins", `{"port":80,"port":443,"allowInsecure":true,"allowInsecure":null}`, "443", "0", "", false},
		{"unknown fields", `{"port":443,"future":{"values":[1,true,null]}}`, "443", "0", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseVmessURL(jsonVMessLink(tc.payload))
			if err != nil {
				t.Fatal(err)
			}
			if got.Port != tc.port || got.Aid != tc.aid || got.Ps != tc.ps || got.AllowInsecure != tc.insecure || got.Net != "tcp" || got.Protocol != "vmess" {
				t.Fatalf("unexpected parsed subscription: %+v", got)
			}
			exported := got.ExportToURL()
			restored, err := ParseVmessURL(exported)
			if err != nil || !reflect.DeepEqual(got, restored) {
				t.Fatalf("export round trip changed subscription: %+v, %v", restored, err)
			}
		})
	}
}

func TestVMessJSONFuzzyBool(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"true", true}, {"false", false}, {"null", false},
		{"0", false}, {"-0.0", false}, {"1", true}, {"-2.5", true}, {"1e2", true},
		{`""`, false}, {`"0"`, false}, {`"1"`, true}, {`"false"`, true}, {`"anything"`, true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			got, err := ParseVmessURL(jsonVMessLink(fmt.Sprintf(`{"allowInsecure":%s}`, tc.value)))
			if err != nil || got.AllowInsecure != tc.want {
				t.Fatalf("allowInsecure=%s: got %+v, %v", tc.value, got, err)
			}
		})
	}
	for _, payload := range []string{
		`{"port":true}`, `{"port":[]}`, `{"port":{}}`,
		`{"allowInsecure":[]}`, `{"allowInsecure":{}}`, `{"allowInsecure":1e999}`,
		`{"port":443} garbage`, `{"port":`,
	} {
		if _, err := ParseVmessURL(jsonVMessLink(payload)); err == nil {
			t.Fatalf("accepted invalid subscription %s", payload)
		}
	}
}

func TestVMessCompactObfsHost(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{`{"host":"cdn.example"}`, "cdn.example"},
		{`{"host":123}`, "123"}, {`{"host":true}`, "true"},
		{`{"host":null}`, ""}, {`{}`, ""}, {``, ""}, {`invalid`, ""},
		{`{"host":"节点.example"}`, "节点.example"},
	} {
		link := jsonVMessLink("auto:"+cipherTestID+"@127.0.0.1:443") + "?" + url.Values{
			"obfsParam": {tc.raw}, "obfs": {"ws"},
		}.Encode()
		got, err := ParseVmessURL(link)
		if err != nil || got.Host != tc.want {
			t.Fatalf("obfsParam=%s: got %+v, %v", tc.raw, got, err)
		}
	}
}
