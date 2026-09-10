// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

func decodeScriptResult(data []byte, budget *membuffer.Budget, limit int64) (_ *Result, err error) {
	var raw struct {
		URL      *string           `json:"url"`
		Headers  map[string]string `json:"headers"`
		Trailers map[string]string `json:"h2_trailers"`
		Body     *string           `json:"body"`
		Binary   *string           `json:"bodyBase64"`
		Status   *int              `json:"status"`
		Response json.RawMessage   `json:"response"`
		Abort    bool              `json:"abort"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid $done result: %w", err)
	}
	r := &Result{URL: raw.URL, Headers: raw.Headers, Trailers: raw.Trailers, Abort: raw.Abort}
	defer func() {
		if err != nil {
			r.Close()
		}
	}()
	if raw.Body != nil || raw.Binary != nil {
		var reader io.Reader
		if raw.Binary != nil {
			reader = base64.NewDecoder(base64.StdEncoding, strings.NewReader(*raw.Binary))
		} else {
			reader = strings.NewReader(*raw.Body)
		}
		r.Body, err = membuffer.Read(reader, limit, budget)
		if err != nil {
			return nil, err
		}
	}
	if raw.Status != nil {
		r.Status = *raw.Status
		if r.Status < 100 || r.Status > 599 {
			return nil, errors.New("$done status must be between 100 and 599")
		}
	}
	if len(raw.Response) > 0 && string(raw.Response) != "null" {
		var err error
		r.Response, err = decodeScriptResult(raw.Response, budget, limit)
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}
