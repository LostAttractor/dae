package v2ray

import (
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strconv"
)

// VMess subscriptions commonly encode port, aid and version as either numbers
// or strings. Keep the daemon's historical fuzzy decoding local to this format,
// rather than installing process-wide JSON decoders.
var vmessUnmarshalers = json.JoinUnmarshalers(
	json.UnmarshalFunc(func(data []byte, value *string) error {
		switch jsontext.Value(data).Kind() {
		case '0':
			*value = string(data)
			return nil
		case 'n':
			*value = ""
			return nil
		case '"':
			return json.Unmarshal(data, value, jsonv1.DefaultOptionsV1())
		default:
			return fmt.Errorf("VMess string field must be a string, number or null")
		}
	}),
	json.UnmarshalFunc(func(data []byte, value *bool) error {
		switch jsontext.Value(data).Kind() {
		case '0':
			number, err := strconv.ParseFloat(string(data), 64)
			if err != nil {
				return err
			}
			*value = number != 0
			return nil
		case '"':
			var text string
			if err := json.Unmarshal(data, &text, jsonv1.DefaultOptionsV1()); err != nil {
				return err
			}
			// Compatibility: historically even "false" is a nonempty,
			// nonzero string and therefore true.
			*value = text != "" && text != "0"
			return nil
		case 'n':
			*value = false
			return nil
		case 't', 'f':
			return json.Unmarshal(data, value)
		default:
			return fmt.Errorf("VMess boolean field must be a boolean, string, number or null")
		}
	}),
)

func vmessObfsHost(raw string) string {
	var params map[string]jsontext.Value
	if err := json.Unmarshal([]byte(raw), &params, jsonv1.DefaultOptionsV1()); err != nil {
		return ""
	}
	value := params["host"]
	switch value.Kind() {
	case 0, 'n':
		return ""
	case '"':
		var host string
		_ = json.Unmarshal(value, &host, jsonv1.DefaultOptionsV1())
		return host
	default:
		return string(value)
	}
}
