package dialer

import (
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
)

// ConnectionIdentity is supplied by the protocol/transport parser that owns
// the configuration. It excludes display metadata and retains every connection
// setting. Callers append global options and the ordered upstream identity.
type ConnectionIdentity interface {
	ConnectionIdentity() string
}

// Credentials and other parsed URL strings may contain arbitrary bytes.
// Encode all string values as base64 so hashing never replaces invalid UTF-8.
var identityStrings = json.MarshalFunc(func(value string) ([]byte, error) {
	return json.Marshal([]byte(value))
})

// ConfigIdentity serializes a data-only, immutable connection configuration.
// Hashing avoids retaining credentials a second time in path-pool map keys.
func ConfigIdentity(kind string, config any) string {
	data, err := json.Marshal(config, json.Deterministic(true), json.WithMarshalers(identityStrings))
	if err != nil {
		panic(fmt.Sprintf("invalid %s connection identity: %v", kind, err))
	}
	return fmt.Sprintf("%s:%x", kind, sha256.Sum256(data))
}
