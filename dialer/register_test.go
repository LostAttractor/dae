package dialer

import (
	"errors"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

func TestNewFromLinkErrorsDoNotExposeCredentials(t *testing.T) {
	const scheme = "registersecret"
	want := errors.New("invalid proxy option")
	fromLinkCreators[scheme] = func(string) (Builder, *Property, error) { return nil, nil, want }
	t.Cleanup(func() { delete(fromLinkCreators, scheme) })
	for _, link := range []string{
		scheme + "://user:secret-password@example.com?token=secret-token",
		scheme + "://user:secret-password@example.com/%zz?token=secret-token",
	} {
		_, _, err := NewFromLink(link)
		if err == nil || strings.Contains(err.Error(), "secret-password") || strings.Contains(err.Error(), "secret-token") {
			t.Fatalf("unsafe parser diagnostic: %v", err)
		}
		if !strings.Contains(link, "%zz") && !errors.Is(err, want) {
			t.Fatalf("creator failure was not preserved: %v", err)
		}
	}
}

func TestNewFromLinkErrorsDoNotExposeMalformedCredentials(t *testing.T) {
	for _, userinfo := range []string{
		"user:secret%xY", "secret%xY:password", "secret%xY",
		"user:secret?%xY", "user:secret/%xY", "user:secret#%xY",
	} {
		_, _, err := NewFromLink("https://" + userinfo + "@example.com")
		if err == nil {
			t.Fatalf("malformed userinfo %q was accepted", userinfo)
		}
		if strings.Contains(err.Error(), "%xY") || strings.Contains(err.Error(), "secret") {
			t.Fatalf("credential bytes in diagnostic: %v", err)
		}
		if !errors.Is(err, InvalidParameterErr) {
			t.Fatalf("malformed URL was not classified as invalid parameters: %v", err)
		}
	}
}

type registerTestDialer struct{}

func (*registerTestDialer) Build(_ *ExtraOption, upstream Upstream) (netproxy.Layer, error) {
	return netproxy.Layer{Data: upstream}, nil
}

func TestNewFromLinkParsesOneLinkAndPreservesAlias(t *testing.T) {
	const scheme = "registertest"
	var receivedLink string
	wantDialer := new(registerTestDialer)
	fromLinkCreators[scheme] = func(link string) (Builder, *Property, error) {
		receivedLink = link
		return wantDialer, &Property{Name: "parsed name", Link: link}, nil
	}
	t.Cleanup(func() { delete(fromLinkCreators, scheme) })

	tests := []struct {
		name  string
		alias string
		link  string
	}{
		{
			name:  "literal arrows",
			alias: "alias->name",
			link:  scheme + "://example.com/path->part?value=left->right#fragment->part",
		},
		{
			name:  "encoded arrows",
			alias: "alias%2D%3Ename",
			link:  scheme + "://example.com/path%2D%3Eother://part?value=left%2D%3Eother://query#fragment%2D%3Eother://part",
		},
		{
			name:  "arrows before schemes in URL components",
			alias: "component arrows",
			link:  scheme + "://example.com/path->other://part?value=left->other://query#fragment->other://part",
		},
		{
			name:  "spaced arrows in query and fragment",
			alias: "spaced component arrows",
			link:  scheme + "://example.com/path?value=left -> other://query#fragment -> other://part",
		},
		{
			name:  "mixed case scheme",
			alias: "mixed case scheme",
			link:  "ReGiStErTeSt://example.com/path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receivedLink = ""
			builder, property, err := NewFromLink(tt.alias + ":  " + tt.link + "  ")
			if err != nil {
				t.Fatal(err)
			}
			if builder != wantDialer {
				t.Fatalf("builder = %#v, want registered builder", builder)
			}
			if receivedLink != tt.link {
				t.Fatalf("creator received %q, want %q", receivedLink, tt.link)
			}
			if property.Name != tt.alias {
				t.Fatalf("property name = %q, want alias %q", property.Name, tt.alias)
			}
		})
	}
}
