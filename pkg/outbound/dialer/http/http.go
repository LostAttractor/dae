package http

import (
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/http"
)

func init() {
	dialer.FromLinkRegister("http", NewHTTP)
	dialer.FromLinkRegister("https", NewHTTP)
}

type HTTP struct {
	Name          string `json:"name"`
	Server        string `json:"server"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	SNI           string `json:"sni"`
	Protocol      string `json:"protocol"`
	AllowInsecure bool   `json:"allowInsecure"`
}

func NewHTTP(link string) (dialer.Builder, *dialer.Property, error) {
	s, err := ParseHTTPURL(link)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", dialer.InvalidParameterErr, err)
	}
	return s, &dialer.Property{
		Name:     s.Name,
		Address:  net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Protocol: s.Protocol,
		Link:     s.ExportToURL(),
	}, nil
}

func ParseHTTPURL(link string) (data *HTTP, err error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("%w: HTTP proxy URL: %v", dialer.InvalidParameterErr, err.(*url.Error).Err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, dialer.InvalidParameterErr
	}
	pwd, _ := u.User.Password()
	strPort := u.Port()
	if strPort == "" {
		if u.Scheme == "http" {
			strPort = "80"
		} else if u.Scheme == "https" {
			strPort = "443"
		}
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, fmt.Errorf("error when parsing port: %w", err)
	}
	allowInsecure, _ := strconv.ParseBool(u.Query().Get("allowInsecure"))
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("allow_insecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("allowinsecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("skipVerify"))
	}
	return &HTTP{
		Name:          u.Fragment,
		Server:        u.Hostname(),
		Port:          port,
		Username:      u.User.Username(),
		Password:      pwd,
		SNI:           u.Query().Get("sni"),
		Protocol:      u.Scheme,
		AllowInsecure: allowInsecure,
	}, nil
}

func (s *HTTP) Build(option *dialer.ExtraOption, upstream dialer.Upstream) (netproxy.Layer, error) {
	u := s.URL()
	return http.BuildHTTPProxy(&u, option, upstream)
}

func (s *HTTP) URL() url.URL {
	u := url.URL{
		Scheme:   s.Protocol,
		Host:     net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Fragment: s.Name,
	}
	query := make(url.Values)
	if s.SNI != "" {
		query.Set("sni", s.SNI)
	}
	if s.AllowInsecure {
		query.Set("allowInsecure", strconv.FormatBool(s.AllowInsecure))
	}
	u.RawQuery = query.Encode()
	if s.Username != "" {
		if s.Password != "" {
			u.User = url.UserPassword(s.Username, s.Password)
		} else {
			u.User = url.User(s.Username)
		}
	}
	return u
}

func (s *HTTP) ExportToURL() string {
	u := s.URL()
	return u.String()
}
