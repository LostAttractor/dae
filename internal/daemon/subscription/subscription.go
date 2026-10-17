/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/proxylink"
	log "github.com/sirupsen/logrus"
)

type sip008 struct {
	Version        int            `json:"version"`
	Servers        []sip008Server `json:"servers"`
	BytesUsed      int64          `json:"bytes_used"`
	BytesRemaining int64          `json:"bytes_remaining"`
}

type sip008Server struct {
	Id         string `json:"id"`
	Remarks    string `json:"remarks"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Plugin     string `json:"plugin"`
	PluginOpts string `json:"plugin_opts"`
}

const (
	maxRemoteSubscriptionSize int64 = 10 * 1024 * 1024
	maxSubscriptionNodes            = 4096
)

// RedactURL hides credentials, query parameters, fragments and remote path
// tokens. Local file paths remain visible so filesystem failures are actionable.
func RedactURL(subscription string) string {
	return resource.RedactURL(subscription)
}

func resolveSubscriptionAsBase64(b []byte) (nodes []string, err error) {
	// base64 decode
	raw, e := proxylink.DecodeBase64(string(b))
	if e != nil {
		raw, _ = proxylink.DecodeBase64URL(string(b))
	}

	// Check and preprocess without materializing an attacker-controlled number
	// of substrings at once.
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(nil, int(maxRemoteSubscriptionSize))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		protocol, suffix, _ := strings.Cut(line, "://")
		if len(protocol) == 0 || len(suffix) == 0 {
			continue
		}
		if len(nodes) == maxSubscriptionNodes {
			return nil, fmt.Errorf("subscription contains more than %d nodes", maxSubscriptionNodes)
		}
		nodes = append(nodes, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan subscription nodes: %w", err)
	}
	return nodes, nil
}

func ResolveSubscriptionAsSIP008(b []byte) (nodes []string, err error) {
	sip, err := decodeSIP008(b)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal json to sip008: %w", err)
	}
	if sip.Version != 1 || sip.Servers == nil {
		return nil, fmt.Errorf("does not seems like a standard sip008 subscription")
	}
	for _, server := range sip.Servers {
		var userinfo *url.Userinfo
		if strings.HasPrefix(server.Method, "2022-") {
			userinfo = url.UserPassword(server.Method, server.Password)
		} else {
			userinfo = url.User(base64.RawURLEncoding.EncodeToString([]byte(server.Method + ":" + server.Password)))
		}
		u := url.URL{
			Scheme:   "ss",
			User:     userinfo,
			Host:     net.JoinHostPort(server.Server, strconv.Itoa(server.ServerPort)),
			Fragment: server.Remarks,
		}
		if server.Plugin != "" {
			plugin := server.Plugin
			if server.PluginOpts != "" {
				plugin += ";" + server.PluginOpts
			}
			u.Path = "/"
			u.RawQuery = url.Values{"plugin": []string{plugin}}.Encode()
		}
		nodes = append(nodes, u.String())
	}
	return nodes, nil
}

func decodeSIP008(b []byte) (sip008, error) {
	decoder := json.NewDecoder(bytes.NewReader(b))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return sip008{}, fmt.Errorf("expected JSON object")
	}
	var sip sip008
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return sip008{}, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return sip008{}, fmt.Errorf("expected object key")
		}
		key = strings.ToLower(key)
		if _, duplicate := seen[key]; duplicate {
			return sip008{}, fmt.Errorf("duplicate SIP008 field %q", key)
		}
		seen[key] = struct{}{}
		switch key {
		case "version":
			err = decoder.Decode(&sip.Version)
		case "bytes_used":
			err = decoder.Decode(&sip.BytesUsed)
		case "bytes_remaining":
			err = decoder.Decode(&sip.BytesRemaining)
		case "servers":
			var start json.Token
			start, err = decoder.Token()
			if err == nil && start != json.Delim('[') {
				err = fmt.Errorf("servers must be an array")
			}
			if err == nil {
				sip.Servers = make([]sip008Server, 0)
			}
			for err == nil && decoder.More() {
				if len(sip.Servers) == maxSubscriptionNodes {
					return sip008{}, fmt.Errorf("subscription contains more than %d nodes", maxSubscriptionNodes)
				}
				var server sip008Server
				if err = decoder.Decode(&server); err == nil {
					sip.Servers = append(sip.Servers, server)
				}
			}
			if err == nil {
				var end json.Token
				end, err = decoder.Token()
				if err == nil && end != json.Delim(']') {
					err = fmt.Errorf("unterminated servers array")
				}
			}
		default:
			var ignored json.RawMessage
			err = decoder.Decode(&ignored)
		}
		if err != nil {
			return sip008{}, err
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		if err == nil {
			err = fmt.Errorf("unterminated JSON object")
		}
		return sip008{}, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return sip008{}, fmt.Errorf("unexpected trailing JSON data")
	}
	return sip, nil
}

func ResolveFile(ctx context.Context, u *url.URL, configDir string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	source, err := resource.Parse(u.String(), configDir)
	if err != nil {
		return nil, err
	}
	if source.Remote() {
		return nil, fmt.Errorf("local subscription requires a file URL")
	}
	root := ""
	if source.Relative {
		if configDir == "" {
			return nil, fmt.Errorf("local subscription requires a configuration directory")
		}
		root = configDir
	}
	file, info, err := resource.OpenLocalFile(source.Location, root)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info.Mode()&0037 > 0 {
		return nil, fmt.Errorf("permissions %04o for '%v' are too open; requires the file is NOT writable by the same group and NOT accessible by others; suggest 0640 or 0600", info.Mode()&0777, source.Location)
	}
	return readSubscriptionFile(ctx, file)
}

func readSubscriptionFile(ctx context.Context, f *os.File) (b []byte, err error) {
	// Resolve the first line instruction.
	fReader := bufio.NewReader(f)
	b, err = fReader.Peek(1)
	if err != nil {
		return nil, err
	}
	if string(b[0]) == "@" {
		// Instruction line. But not support yet.
		_, _, err = fReader.ReadLine()
		if err != nil {
			return nil, err
		}
	}

	b, err = resource.ReadBounded(ctx, fReader, maxRemoteSubscriptionSize)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(b), err
}

func resolveSubscriptionContent(ctx context.Context, b []byte, validateNode func(string) error) ([]string, error) {
	if validateNode == nil {
		return nil, fmt.Errorf("node validator is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var nodes []string
	if nodes, err := ResolveSubscriptionAsSIP008(b); err == nil {
		log.WithField("format", "sip008").Trace("Parsed subscription content")
		return validateSubscriptionNodes(ctx, nodes, validateNode)
	}
	nodes, err := resolveSubscriptionAsBase64(b)
	if err != nil {
		return nil, err
	}
	log.WithField("format", "base64").Trace("Parsed subscription content")
	return validateSubscriptionNodes(ctx, nodes, validateNode)
}

func validateSubscriptionNodes(ctx context.Context, nodes []string, validateNode func(string) error) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("subscription contains no nodes")
	}

	validNodes := make([]string, 0, len(nodes))
	var firstValidationErr error
	invalidNodes := 0
	for i, node := range nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := validateNodeSafely(validateNode, node); err != nil {
			invalidNodes++
			if firstValidationErr == nil {
				firstValidationErr = fmt.Errorf("node %d: %w", i+1, err)
			}
			continue
		}
		validNodes = append(validNodes, node)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if invalidNodes > 0 {
		log.WithFields(log.Fields{"discarded_nodes": invalidNodes, "usable_nodes": len(validNodes)}).WithError(firstValidationErr).Debug("Discarded unusable subscription nodes")
	}
	if len(validNodes) == 0 {
		return nil, fmt.Errorf("subscription contains no usable nodes: %w", firstValidationErr)
	}
	return validNodes, nil
}

func validateNodeSafely(validateNode func(string) error, node string) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("node validator panicked")
		}
	}()
	return validateNode(node)
}

type ResolveOptions struct {
	BaseDir         string
	CacheDir        string
	RefreshDeadline time.Time
}

func ResolveSubscriptionContext(ctx context.Context, client *http.Client, options ResolveOptions, subscription string, validateNode func(string) error) (tag string, nodes []string, err error) {
	defer func() { err = resource.RedactError(err) }()
	if validateNode == nil {
		return "", nil, fmt.Errorf("node validator is required")
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}

	tag, subscription = resource.Split(subscription)

	source, err := resource.Parse(subscription, options.BaseDir)
	if err != nil {
		return tag, nil, fmt.Errorf("failed to parse subscription %q: %w", RedactURL(subscription), resource.RedactError(err))
	}
	log.WithFields(log.Fields{"subscription": tag, "source": RedactURL(subscription)}).Debug("Loading subscription")
	var b []byte

	if !source.Remote() {
		u, parseErr := url.Parse(subscription)
		if parseErr != nil {
			return tag, nil, resource.RedactError(parseErr)
		}
		b, err = ResolveFile(ctx, u, options.BaseDir)
		if err != nil {
			return "", nil, err
		}
		nodes, err = resolveSubscriptionContent(ctx, b, validateNode)
		if err != nil {
			return "", nil, fmt.Errorf("direct subscription file is unusable: %w", err)
		}
		return tag, nodes, nil
	}
	cache := resource.Cache{Dir: options.CacheDir}
	nodes, status, err := cache.Load(ctx, client, resource.LoadOptions{
		Key: source.Location, MaxBytes: maxRemoteSubscriptionSize, RefreshDeadline: options.RefreshDeadline,
	}, func(read resource.ReadFunc) ([]string, error) {
		result, err := read(source, resource.ReadOptions{MaxBytes: maxRemoteSubscriptionSize,
			UserAgent: fmt.Sprintf("dae/%v (like v2rayA/1.0 WebRequestHelper) (like v2rayN/1.0 WebRequestHelper)", config.Version)})
		if err != nil {
			return nil, err
		}
		return resolveSubscriptionContent(ctx, bytes.TrimSpace(result.Data), validateNode)
	})
	if err != nil {
		return tag, nil, err
	}
	logger := log.WithFields(log.Fields{"subscription": tag, "source": RedactURL(subscription), "nodes": len(nodes)})
	if status.RefreshError != nil {
		logger.WithError(status.RefreshError).Warn("Subscription update failed; using cached nodes")
	}
	if status.WriteError != nil {
		logger.WithError(status.WriteError).Warn("Subscription loaded, but its resource cache could not be updated")
	}
	return tag, nodes, nil
}
