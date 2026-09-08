// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/daeuniverse/dae/component/mitm/surge/internal/quickjs"
	"github.com/daeuniverse/dae/pkg/membuffer"
	log "github.com/sirupsen/logrus"
)

// scriptExecution belongs to one VM on one OS thread. HTTP goroutines only
// send events; host calls and callbacks update this state on the VM thread.
type scriptExecution struct {
	httpWorkers            sync.WaitGroup
	runtime                *Runtime
	ctx                    context.Context
	client                 *http.Client
	timeout                time.Duration
	dom                    *runtimeDOM
	events                 chan runtimeEvent
	timers                 []runtimeTimer
	pendingHTTP, totalHTTP int
	result                 *Result
	bodyMemory             *membuffer.Budget
	bodyLimit              int64
	bodyError              error
}

type runtimeEvent struct {
	id     int
	data   string
	memory membuffer.Reservation
}

type runtimeTimer struct {
	id   int
	when time.Time
}

func (s *scriptExecution) hostCall(args []string) (any, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	arg := func(i int) string {
		if i >= len(args) {
			return ""
		}
		return args[i]
	}
	switch arg(0) {
	case "url":
		return runtimeURL(arg(1), arg(2), arg(3), arg(4))
	case "ungzip":
		return runtimeUngzip(s.ctx, arg(1), min(s.runtime.opts.MemoryLimit/4, 32<<20))
	case "dom":
		return s.dom.call(arg(1), arg(2), arg(3))
	case "done":
		if s.result == nil {
			result, err := decodeScriptResult([]byte(arg(1)), s.bodyMemory, s.bodyLimit)
			if err != nil {
				s.bodyError = err
				return nil, err
			}
			s.result = result
		}
		return nil, nil
	case "log":
		level, err := log.ParseLevel(arg(1))
		if err != nil || level < log.ErrorLevel {
			return nil, errors.New("invalid script log level")
		}
		if s.runtime.opts.Logger != nil {
			s.runtime.opts.Logger.Log(level, arg(2))
		}
		return nil, nil
	case "read":
		return s.runtime.data.read(arg(1)), nil
	case "write":
		return s.runtime.data.write(arg(1), arg(2), arg(3) == "delete"), nil
	case "encode":
		return base64.StdEncoding.EncodeToString([]byte(arg(1))), nil
	case "decode":
		data, err := base64.StdEncoding.DecodeString(arg(1))
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(data) && arg(2) == "fatal" {
			return nil, errors.New("invalid UTF-8 data")
		}
		text := strings.ToValidUTF8(string(data), "\ufffd")
		if arg(3) != "keep-bom" {
			text = strings.TrimPrefix(text, "\ufeff")
		}
		return text, nil
	case "timer":
		if len(s.timers) >= 1024 {
			return nil, errors.New("too many pending script timers")
		}
		id, _ := strconv.Atoi(arg(1))
		ms, parseErr := strconv.ParseInt(arg(2), 10, 64)
		if parseErr != nil || ms < 0 {
			ms = 0
		}
		ms = min(ms, s.timeout.Milliseconds()+1)
		s.timers = append(s.timers, runtimeTimer{id, time.Now().Add(time.Duration(ms) * time.Millisecond)})
		return nil, nil
	case "clear-timer":
		id, _ := strconv.Atoi(arg(1))
		for i := range s.timers {
			if s.timers[i].id == id {
				s.timers = append(s.timers[:i], s.timers[i+1:]...)
				break
			}
		}
		return nil, nil
	case "http":
		if s.totalHTTP >= 64 || s.pendingHTTP >= 16 {
			return nil, errors.New("script HTTP request limit exceeded")
		}
		id, _ := strconv.Atoi(arg(1))
		spec := arg(2)
		s.pendingHTTP++
		s.totalHTTP++
		s.httpWorkers.Go(func() {
			data, memory, err := scriptHTTP(s.ctx, s.client, spec, min(s.runtime.opts.MemoryLimit/4, 32<<20), s.bodyMemory)
			if err != nil {
				failure, _ := json.Marshal(map[string]any{"error": err.Error()})
				data = string(failure)
			}
			select {
			case s.events <- runtimeEvent{id: id, data: data, memory: memory}:
			case <-s.ctx.Done():
				memory.Close()
			}
		})
		return nil, nil
	default:
		return nil, errors.New("unknown script host operation")
	}
}

func (s *scriptExecution) waitResult(vm *quickjs.VM) (*Result, error) {
	for {
		if err := vm.ExecutePendingJobs(); err != nil {
			return nil, fmt.Errorf("execute Surge script promise: %w", err)
		}
		if s.result != nil {
			return s.result, nil
		}
		if s.pendingHTTP == 0 && len(s.timers) == 0 {
			return nil, ErrMissingDone
		}
		var timer *time.Timer
		var timerC <-chan time.Time
		next := -1
		for i := range s.timers {
			if next == -1 || s.timers[i].when.Before(s.timers[next].when) {
				next = i
			}
		}
		if next >= 0 {
			timer = time.NewTimer(max(time.Until(s.timers[next].when), 0))
			timerC = timer.C
		}
		var event runtimeEvent
		select {
		case <-s.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil, s.ctx.Err()
		case <-timerC:
			event = runtimeEvent{id: s.timers[next].id, data: "null"}
			s.timers = append(s.timers[:next], s.timers[next+1:]...)
		case event = <-s.events:
			s.pendingHTTP--
		}
		if timer != nil {
			timer.Stop()
		}
		err := vm.Dispatch(event.id, event.data)
		event.memory.Close()
		if err != nil {
			return nil, fmt.Errorf("execute Surge script callback: %w", err)
		}
	}
}

func scriptHTTP(ctx context.Context, client *http.Client, spec string, maxBody int64, budget *membuffer.Budget) (string, membuffer.Reservation, error) {
	var options struct {
		URL     string            `json:"url"`
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
		Body    *string           `json:"body"`
		Binary  *string           `json:"bodyBase64"`
		Timeout float64           `json:"timeout"`
	}
	if err := json.Unmarshal([]byte(spec), &options); err != nil {
		return "", membuffer.Reservation{}, err
	}
	if options.Timeout > 0 && options.Timeout < 86400 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(options.Timeout*float64(time.Second)))
		defer cancel()
	}
	var body []byte
	if options.Body != nil {
		body = []byte(*options.Body)
	}
	if options.Binary != nil {
		var err error
		body, err = base64.StdEncoding.DecodeString(*options.Binary)
		if err != nil {
			return "", membuffer.Reservation{}, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, options.Method, options.URL, bytes.NewReader(body))
	if err != nil {
		return "", membuffer.Reservation{}, err
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return "", membuffer.Reservation{}, errors.New("$httpClient only supports http and https")
	}
	for k, v := range options.Headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", membuffer.Reservation{}, err
	}
	defer resp.Body.Close()
	data, err := membuffer.Read(resp.Body, maxBody, budget)
	defer data.Close()
	if err != nil {
		return "", membuffer.Reservation{}, err
	}
	message := map[string]any{"status": resp.StatusCode, "headers": messageHeaders(resp.Header)}
	if len(resp.Trailer) > 0 {
		message["h2_trailers"] = messageHeaders(resp.Trailer)
	}
	// []byte is serialized as base64 by JSON without a separately retained
	// base64 string. Charge the event until Dispatch consumes it or cancellation.
	writer := &membuffer.Buffer{Budget: budget, Limit: 2*maxBody + 1<<20}
	defer writer.Close()
	if err := jsonv2.MarshalWrite(writer, map[string]any{"response": message, "bodyBase64": data.Bytes()}); err != nil {
		return "", membuffer.Reservation{}, err
	}
	view := writer.View()
	defer view.Close()
	memory, err := budget.Reserve(int64(len(view.Bytes())))
	if err != nil {
		return "", membuffer.Reservation{}, err
	}
	return string(view.Bytes()), memory, nil
}
