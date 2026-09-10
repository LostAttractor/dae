package surge

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

var ErrMissingDone = errors.New("script completed without calling $done")

// Message is the request or response exposed to a Surge script. A nil Body
// omits the body property, as required when requires-body is disabled.
type Message struct {
	URL, Method, ID string
	Headers         map[string]string
	Trailers        map[string]string
	Body            []byte
	Status          int
}

func messageHeaders(header http.Header) map[string]string {
	result := make(map[string]string, len(header))
	for key, values := range header {
		result[key] = strings.Join(values, ", ")
	}
	return result
}

type Invocation struct {
	Request, Response                *Message
	ScriptName, ScriptType, Argument string
	BinaryBodyMode                   bool
	Timeout                          time.Duration
	HTTPClient                       *http.Client
	BodyMemory                       *membuffer.Budget
	BodyLimit                        int64
}

// Result distinguishes an omitted body from replacing the body with empty data.
type Result struct {
	URL      *string
	Headers  map[string]string
	Trailers map[string]string
	Body     *membuffer.View
	Status   int
	Response *Result
	Abort    bool
}

type RuntimeOptions struct {
	MemoryLimit int64
	Timeout     time.Duration
	StorePath   string
	Log         func(level, message string)
}

// The engine transfers body ownership to the exchange before releasing results.
func (r *Result) Close() {
	if r != nil {
		r.Body.Close()
		r.Response.Close()
	}
}
