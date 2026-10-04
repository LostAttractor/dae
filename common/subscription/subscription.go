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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/config"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
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

func ResolveSubscriptionAsBase64(b []byte) (nodes []string) {
	nodes, _ = resolveSubscriptionAsBase64(b)
	return nodes
}

func resolveSubscriptionAsBase64(b []byte) (nodes []string, err error) {
	// base64 decode
	raw, e := common.Base64StdDecode(string(b))
	if e != nil {
		raw, _ = common.Base64UrlDecode(string(b))
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

func ResolveFile(u *url.URL, configDir string) (b []byte, err error) {
	source, err := resource.Parse(u.String(), configDir)
	if err != nil {
		return nil, err
	}
	if source.Remote() {
		return nil, fmt.Errorf("local subscription requires a file URL")
	}
	path := source.Location
	var f *os.File
	if !source.Relative {
		// An explicit absolute path may name a rotating secret symlink, such
		// as /run/secrets. Validate the opened target below, rather than
		// rejecting links or resolving them once before opening the file.
		f, err = openAbsoluteSubscriptionFile(path)
	} else {
		// file:relative/path resolves within the configuration directory.
		if configDir == "" {
			return nil, fmt.Errorf("local subscription requires a configuration directory")
		}
		configDir, err = filepath.Abs(configDir)
		if err != nil {
			return nil, err
		}
		if err = common.EnsureFileInSubDir(path, configDir); err != nil {
			return nil, err
		}
		f, err = openSubscriptionFile(configDir, path)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readSubscriptionFile(f, path)
}

func openAbsoluteSubscriptionFile(path string) (*os.File, error) {
	// O_NONBLOCK prevents a named pipe from hanging before the regular-file
	// check. Fstat and reads use the same descriptor even if a secret rotates.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open subscription file", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openSubscriptionFile(configDir, path string) (*os.File, error) {
	relative, err := filepath.Rel(configDir, path)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(filepath.Clean(relative), string(filepath.Separator))
	if len(parts) == 0 || parts[0] == "." || parts[0] == ".." {
		return nil, fmt.Errorf("invalid relative subscription path %q", relative)
	}

	dirFd, err := unix.Open(configDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open subscription directory", Path: configDir, Err: err}
	}
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if i != len(parts)-1 {
			flags |= unix.O_DIRECTORY
		} else {
			flags |= unix.O_NONBLOCK
		}
		fd, openErr := unix.Openat(dirFd, part, flags, 0)
		if openErr != nil {
			componentPath := filepath.Join(configDir, filepath.Join(parts[:i+1]...))
			pathErr := subscriptionFileOpenError(dirFd, part, componentPath, openErr)
			_ = unix.Close(dirFd)
			return nil, pathErr
		}
		_ = unix.Close(dirFd)
		if i == len(parts)-1 {
			return os.NewFile(uintptr(fd), path), nil
		}
		dirFd = fd
	}
	return nil, fmt.Errorf("invalid subscription path %q", path)
}

func subscriptionFileOpenError(dirFd int, name, path string, err error) error {
	// Linux reports ENOTDIR, rather than ELOOP, when O_NOFOLLOW and
	// O_DIRECTORY reject an intermediate symlink. Inspect only for diagnostics;
	// the failed open is never retried with weaker flags.
	if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		var stat unix.Stat_t
		if unix.Fstatat(dirFd, name, &stat, unix.AT_SYMLINK_NOFOLLOW) == nil && stat.Mode&unix.S_IFMT == unix.S_IFLNK {
			err = fmt.Errorf("symbolic links are not allowed: %w", err)
		}
	}
	return &os.PathError{Op: "open subscription path", Path: path, Err: err}
}

func readSubscriptionFile(f *os.File, path string) (b []byte, err error) {
	// Check file access.
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("subscription file is not a regular file: %v", path)
	}
	if fi.Mode()&0037 > 0 {
		return nil, fmt.Errorf("permissions %04o for '%v' are too open; requires the file is NOT writable by the same group and NOT accessible by others; suggest 0640 or 0600", fi.Mode()&0777, path)
	}
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

	b, err = io.ReadAll(io.LimitReader(fReader, maxRemoteSubscriptionSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxRemoteSubscriptionSize {
		return nil, fmt.Errorf("subscription file exceeds %d bytes", maxRemoteSubscriptionSize)
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

func validateManagedDir(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("subscription directory %q cannot be a symbolic link", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("subscription path %q is not a directory", path)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("permissions %04o for subscription directory %q are unsafe; group and others must not have write access", info.Mode().Perm(), path)
	}
	return nil
}

func openManagedDir(path string, create bool) (*os.File, error) {
	if create {
		if err := os.MkdirAll(path, 0700); err != nil {
			return nil, fmt.Errorf("create directory %q: %w", path, err)
		}
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect directory %q: %w", path, err)
	}
	if err := validateManagedDir(path, before); err != nil {
		return nil, err
	}

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open directory %q securely: %w", path, err)
	}
	dir := os.NewFile(uintptr(fd), path)
	after, err := dir.Stat()
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("inspect opened directory %q: %w", path, err)
	}
	if err := validateManagedDir(path, after); err != nil {
		_ = dir.Close()
		return nil, err
	}
	if !os.SameFile(before, after) {
		_ = dir.Close()
		return nil, fmt.Errorf("directory %q was replaced while opening it", path)
	}
	return dir, nil
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
		b, err = ResolveFile(u, options.BaseDir)
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
