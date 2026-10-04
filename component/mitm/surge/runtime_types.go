package surge

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
	log "github.com/sirupsen/logrus"
)

// Message is the request or response exposed to a Surge script. Empty bodies
// omit the body property; nil also represents requires-body being disabled.
type Message struct {
	URL, Method, ID string
	Headers         http.Header
	Trailers        http.Header
	Body            []byte
	Status          int
}

func messageHeaders(header http.Header) map[string]string {
	result := make(map[string]string, len(header))
	for key, values := range header {
		separator := ", "
		if strings.EqualFold(key, "Cookie") {
			separator = "; "
		}
		result[key] = strings.Join(values, separator)
	}
	return result
}

// net/http preserves duplicate values, but not wire order across field names.
func runtimeHeaders(header http.Header, full bool) any {
	if !full {
		return messageHeaders(header)
	}
	type field struct {
		Field string `json:"field"`
		Value string `json:"value"`
	}
	fields := make([]field, 0, len(header))
	for _, name := range slices.Sorted(maps.Keys(header)) {
		for _, value := range header[name] {
			fields = append(fields, field{name, value})
		}
	}
	return fields
}

type Invocation struct {
	Domain                           string
	CronExp                          string
	Trigger                          string
	Request, Response                *Message
	ScriptName, ScriptType, Argument string
	ScriptPath                       string
	ArgumentSet                      bool
	ModuleName                       string
	BinaryBodyMode                   bool
	FullHeaderMode                   bool
	Timeout                          time.Duration
	HTTPClient                       *http.Client
	BodyMemory                       *membuffer.Budget
	BodyLimit                        int64
}

// Result distinguishes an omitted body from replacing the body with empty data.
type Result struct {
	DNS      DNSResult
	URL      *string
	Headers  http.Header
	Trailers http.Header
	Body     *membuffer.View
	Status   int
	Response *Result
	Abort    bool
}

type DNSResult struct {
	Address   string   `json:"address"`
	Addresses []string `json:"addresses"`
	Server    string   `json:"server"`
	Servers   []string `json:"servers"`
	TTL       *uint32  `json:"ttl"`
}

type RuntimeOptions struct {
	MemoryLimit int64
	Timeout     time.Duration
	StorePath   string
	Logger      *log.Entry
}

// The engine transfers body ownership to the exchange before releasing results.
func (r *Result) Close() {
	if r != nil {
		r.Body.Close()
		r.Response.Close()
	}
}
