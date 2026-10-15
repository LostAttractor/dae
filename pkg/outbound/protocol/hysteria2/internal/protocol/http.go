package protocol

import (
	"errors"
	"net/http"
	"strconv"
)

const (
	URLHost = "hysteria"
	URLPath = "/auth"

	RequestHeaderAuth        = "Hysteria-Auth"
	ResponseHeaderUDPEnabled = "Hysteria-UDP"
	CommonHeaderCCRX         = "Hysteria-CC-RX"
	CommonHeaderPadding      = "Hysteria-Padding"

	StatusAuthOK = 233
)

// AuthRequest is what client sends to server for authentication.
type AuthRequest struct {
	Auth string
	Rx   uint64 // 0 = unknown, client asks server to use bandwidth detection
}

// AuthResponse is what server sends to client when authentication is passed.
type AuthResponse struct {
	UDPEnabled bool
	Rx         uint64 // 0 = unlimited
	RxAuto     bool   // true = server asks client to use bandwidth detection
}

func AuthRequestToHeader(h http.Header, req AuthRequest) {
	h.Set(RequestHeaderAuth, req.Auth)
	h.Set(CommonHeaderCCRX, strconv.FormatUint(req.Rx, 10))
	h.Set(CommonHeaderPadding, authRequestPadding.String())
}

func AuthResponseFromHeader(h http.Header) (AuthResponse, error) {
	resp := AuthResponse{}
	resp.UDPEnabled, _ = strconv.ParseBool(h.Get(ResponseHeaderUDPEnabled))
	rxStr := h.Get(CommonHeaderCCRX)
	if rxStr == "auto" {
		// Special case for server requesting client to use bandwidth detection
		resp.RxAuto = true
	} else if rxStr != "" {
		rx, err := strconv.ParseUint(rxStr, 10, 64)
		if err != nil {
			return AuthResponse{}, errors.New("invalid Hysteria-CC-RX response header")
		}
		resp.Rx = rx
	}
	return resp, nil
}
