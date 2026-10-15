// SPDX-License-Identifier: AGPL-3.0-only

package jq

import (
	"bytes"
	"container/list"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/itchyny/gojq"
)

const maxPrograms = 32

type compiled struct {
	expression string
	code       *gojq.Code
}
type compiler struct {
	entries map[string]*list.Element
	recent  list.List
}

func (c *compiler) get(expression string) (*gojq.Code, error) {
	if entry := c.entries[expression]; entry != nil {
		c.recent.MoveToFront(entry)
		return entry.Value.(compiled).code, nil
	}
	query, err := gojq.Parse(expression)
	if err != nil {
		return nil, err
	}
	// No environment, filesystem loader, input iterator or custom host functions.
	code, err := gojq.Compile(query)
	if err != nil {
		return nil, err
	}
	if c.entries == nil {
		c.entries = make(map[string]*list.Element)
	}
	if len(c.entries) == maxPrograms {
		old := c.recent.Back()
		delete(c.entries, old.Value.(compiled).expression)
		c.recent.Remove(old)
	}
	c.entries[expression] = c.recent.PushFront(compiled{expression, code})
	return code, nil
}

// Serve is called only by the plugin's hidden child entry point. All parsing,
// compilation and JSON expansion run after the parent installed cgroup limits.
func Serve(input io.Reader, output io.Writer) error {
	var cache compiler
	for {
		request, err := readFrame(input)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if request.Expression == 0 || request.Expression > MaxExpression || request.Body > MaxBody || request.Limit == 0 || request.Limit > MaxBody || request.Validate > 1 {
			return errors.New("jq request exceeds protocol limits")
		}
		expression := make([]byte, request.Expression)
		if _, err := io.ReadFull(input, expression); err != nil {
			return err
		}
		body := make([]byte, request.Body)
		if _, err := io.ReadFull(input, body); err != nil {
			return err
		}
		result, err := evaluate(&cache, string(expression), body, int64(request.Limit), request.Validate != 0)
		response := frame{Magic: frameMagic, Generation: request.Generation, Job: request.Job, Status: statusOK}
		var data []byte
		if err != nil {
			response.Status = statusError
			if errors.Is(err, membuffer.ErrTooLarge) {
				response.Status = statusLarge
			}
			data = []byte(err.Error()[:min(len(err.Error()), maxError)])
		} else if result == nil {
			response.Status = statusEmpty
		} else {
			data = result.Bytes()
		}
		response.Body = uint32(len(data))
		err = writeFrame(output, response)
		if err == nil {
			_, err = output.Write(data)
		}
		result.Close()
		if err != nil {
			return err
		}
	}
}

func evaluate(cache *compiler, expression string, body []byte, limit int64, validate bool) (*membuffer.View, error) {
	code, err := cache.get(expression)
	if err != nil {
		return nil, fmt.Errorf("Body Rewrite jq: %w", err)
	}
	if validate {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var input any
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("Body Rewrite requires valid JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("Body Rewrite requires one JSON document")
	}
	writer := &membuffer.Buffer{Limit: limit, Budget: membuffer.NewBudget(2 * limit)}
	defer writer.Close()
	iterator := code.RunWithContext(context.Background(), input)
	for {
		value, ok := iterator.Next()
		if !ok {
			break
		}
		if err, ok := value.(error); ok {
			return nil, fmt.Errorf("Body Rewrite jq: %w", err)
		}
		if writer.Len() != 0 {
			if _, err := io.WriteString(writer, "\n"); err != nil {
				return nil, err
			}
		}
		if err := jsonv2.MarshalWrite(writer, value, jsonv2.Deterministic(true)); err != nil {
			return nil, fmt.Errorf("Body Rewrite jq output: %w", err)
		}
	}
	if writer.Len() == 0 {
		return nil, nil
	}
	return writer.View(), nil
}

// Error messages are untrusted expression output and remain bounded on the wire.
func responseError(data []byte) error {
	return fmt.Errorf("%w: %s", ErrExpression, strings.ToValidUTF8(string(data), "�"))
}
