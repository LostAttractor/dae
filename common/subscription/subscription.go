/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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
	"syscall"

	"github.com/daeuniverse/dae/common"
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

func fetchRemoteSubscription(client *http.Client, subscription string) ([]byte, error) {
	return fetchRemoteSubscriptionContext(context.Background(), client, subscription)
}

func fetchRemoteSubscriptionContext(ctx context.Context, client *http.Client, subscription string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subscription, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("dae/%v (like v2rayA/1.0 WebRequestHelper) (like v2rayN/1.0 WebRequestHelper)", config.Version))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("subscription request returned HTTP status %d", resp.StatusCode)
	}
	if resp.ContentLength > maxRemoteSubscriptionSize {
		return nil, fmt.Errorf("subscription response is too large: %d bytes exceeds %d", resp.ContentLength, maxRemoteSubscriptionSize)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteSubscriptionSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxRemoteSubscriptionSize {
		return nil, fmt.Errorf("subscription response exceeds %d bytes", maxRemoteSubscriptionSize)
	}
	return b, nil
}

func ResolveSubscriptionAsBase64(b []byte) (nodes []string) {
	nodes, _ = resolveSubscriptionAsBase64(b)
	return nodes
}

func resolveSubscriptionAsBase64(b []byte) (nodes []string, err error) {
	log.Traceln("Try to resolve as base64")

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
	log.Traceln("Try to resolve as sip008")

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
	if u.Host == "" {
		return nil, fmt.Errorf("not support absolute path")
	}
	/// Relative location.
	// Make sure path is secure.
	path := filepath.Join(configDir, u.Host, u.Path)
	if err = common.EnsureFileInSubDir(path, configDir); err != nil {
		return nil, err
	}
	/// Read and resolve.
	f, err := openSubscriptionFile(configDir, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readSubscriptionFile(f, path)
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
		return nil, err
	}
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if i != len(parts)-1 {
			flags |= unix.O_DIRECTORY
		} else {
			flags |= unix.O_NONBLOCK
		}
		fd, openErr := unix.Openat(dirFd, part, flags, 0)
		_ = unix.Close(dirFd)
		if openErr != nil {
			return nil, openErr
		}
		if i == len(parts)-1 {
			return os.NewFile(uintptr(fd), path), nil
		}
		dirFd = fd
	}
	return nil, fmt.Errorf("invalid subscription path %q", path)
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
		log.Debugln("Resolve as sip008")
		return validateSubscriptionNodes(ctx, nodes, validateNode)
	} else {
		log.Traceln(err)
	}
	nodes, err := resolveSubscriptionAsBase64(b)
	if err != nil {
		return nil, err
	}
	log.Debugln("Resolve as base64")
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
		if err := validateNode(node); err != nil {
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
		log.Debugf("discarded %d unusable subscription nodes; first error: %v", invalidNodes, firstValidationErr)
	}
	if len(validNodes) == 0 {
		return nil, fmt.Errorf("subscription contains no usable nodes: %w", firstValidationErr)
	}
	return validNodes, nil
}

func validatePersistDir(path string, info os.FileInfo) error {
	return validateManagedDir(path, info, true)
}

func validateManagedDir(path string, info os.FileInfo, requireOwner bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("persist directory %q cannot be a symbolic link", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("persist path %q is not a directory", path)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("permissions %04o for persist directory %q are unsafe; group and others must not have write access", info.Mode().Perm(), path)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); requireOwner && (!ok || stat.Uid != uint32(os.Geteuid())) {
		return fmt.Errorf("persist directory %q is not owned by effective uid %d", path, os.Geteuid())
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
	if err := validateManagedDir(path, before, false); err != nil {
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
	if err := validateManagedDir(path, after, false); err != nil {
		_ = dir.Close()
		return nil, err
	}
	if !os.SameFile(before, after) {
		_ = dir.Close()
		return nil, fmt.Errorf("directory %q was replaced while opening it", path)
	}
	return dir, nil
}

func openPersistDir(subscriptionDir string, create bool) (*os.File, error) {
	path := filepath.Join(subscriptionDir, "persist.d")
	var before os.FileInfo
	if !create {
		var err error
		before, err = os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("inspect persist directory %q: %w", path, err)
		}
	}
	parent, err := openManagedDir(subscriptionDir, create)
	if err != nil {
		return nil, err
	}
	defer parent.Close()

	created := false
	if create {
		if err := unix.Mkdirat(int(parent.Fd()), "persist.d", 0700); err == nil {
			created = true
		} else if !errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("create persist directory: %w", err)
		}
	}
	if before == nil {
		before, err = os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("inspect persist directory %q: %w", path, err)
		}
	}
	if err := validatePersistDir(path, before); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(parent.Fd()), "persist.d", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open persist directory %q securely: %w", path, err)
	}
	dir := os.NewFile(uintptr(fd), path)
	after, err := dir.Stat()
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("inspect opened persist directory %q: %w", path, err)
	}
	if err := validatePersistDir(path, after); err != nil {
		_ = dir.Close()
		return nil, err
	}
	if !os.SameFile(before, after) {
		_ = dir.Close()
		return nil, fmt.Errorf("persist directory %q was replaced while opening it", path)
	}
	if created {
		if err := parent.Sync(); err != nil {
			_ = dir.Close()
			return nil, fmt.Errorf("sync subscription directory: %w", err)
		}
	}
	return dir, nil
}

func readPersistedSubscription(dir *os.File, name string) ([]byte, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open cached subscription %q: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("cached subscription %q is not owned by effective uid %d", name, os.Geteuid())
	}
	return readSubscriptionFile(file, filepath.Join(dir.Name(), name))
}

func persistSubscription(dir *os.File, name string, b []byte) error {
	var (
		file    *os.File
		tmpName string
	)
	for range 100 {
		var suffix [16]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return fmt.Errorf("generate temporary subscription name: %w", err)
		}
		tmpName = "." + name + ".tmp-" + hex.EncodeToString(suffix[:])
		fd, err := unix.Openat(int(dir.Fd()), tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return fmt.Errorf("create temporary subscription: %w", err)
		}
		file = os.NewFile(uintptr(fd), tmpName)
		break
	}
	if file == nil {
		return fmt.Errorf("create temporary subscription: too many name collisions")
	}

	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		_ = unix.Unlinkat(int(dir.Fd()), tmpName, 0)
	}()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(b); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	if err := unix.Renameat(int(dir.Fd()), tmpName, int(dir.Fd()), name); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync persist directory: %w", err)
	}
	return nil
}

// PrunePersistedSubscriptions removes cache entries whose tags are not active.
func PrunePersistedSubscriptions(subscriptionDir string, activeTags map[string]struct{}) error {
	dir, err := openPersistDir(subscriptionDir, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer dir.Close()

	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	removed := false
	var stale []string
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sub") {
			continue
		}
		if entry.IsDir() {
			return fmt.Errorf("persisted subscription %q is a directory", entry.Name())
		}
		tag := strings.TrimSuffix(entry.Name(), ".sub")
		if _, ok := activeTags[tag]; ok {
			continue
		}
		stale = append(stale, entry.Name())
	}
	for _, name := range stale {
		if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil {
			if removed {
				_ = dir.Sync()
			}
			return fmt.Errorf("remove stale persisted subscription %q: %w", name, err)
		}
		removed = true
	}
	if removed {
		return dir.Sync()
	}
	return nil
}

func validPersistenceTag(tag string) bool {
	return tag != "" && tag != "." && tag != ".." && filepath.Base(tag) == tag &&
		!strings.ContainsAny(tag, `/\`) && !strings.ContainsRune(tag, 0)
}

// PersistentTag returns the cache tag for a configured persistent remote
// subscription. It does not retain tags from ordinary HTTP or local sources.
func PersistentTag(subscription string) (string, bool) {
	tag, raw := common.GetTagFromLinkLikePlaintext(subscription)
	if !validPersistenceTag(tag) {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http-file" && u.Scheme != "https-file") {
		return "", false
	}
	return tag, true
}

func ResolveSubscription(client *http.Client, subscriptionDir string, subscription string, validateNode func(string) error) (tag string, nodes []string, err error) {
	return ResolveSubscriptionContext(context.Background(), client, subscriptionDir, subscription, validateNode)
}

func ResolveSubscriptionContext(ctx context.Context, client *http.Client, subscriptionDir string, subscription string, validateNode func(string) error) (tag string, nodes []string, err error) {
	if validateNode == nil {
		return "", nil, fmt.Errorf("node validator is required")
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}

	/// Get tag.
	tag, subscription = common.GetTagFromLinkLikePlaintext(subscription)

	/// Parse url.
	u, err := url.Parse(subscription)
	if err != nil {
		return tag, nil, fmt.Errorf("failed to parse subscription \"%v\": %w", subscription, err)
	}
	log.Debugf("ResolveSubscription: %v", subscription)
	var b []byte

	persistToFile := false

	switch u.Scheme {
	case "file":
		b, err = ResolveFile(u, subscriptionDir)
		if err != nil {
			return "", nil, err
		}
		nodes, err = resolveSubscriptionContent(ctx, b, validateNode)
		if err != nil {
			return "", nil, fmt.Errorf("direct subscription file is unusable: %w", err)
		}
		return tag, nodes, nil
	case "http-file", "https-file":
		if len(tag) == 0 {
			return "", nil, fmt.Errorf("tag is required for http-file/https-file subscription")
		}
		if !validPersistenceTag(tag) {
			return "", nil, fmt.Errorf("invalid persistence tag %q: must be a safe basename without path separators", tag)
		}
		persistToFile = true
		subscription = strings.Replace(subscription, "-file", "", 1)
	}
	b, err = fetchRemoteSubscriptionContext(ctx, client, subscription)
	if err == nil {
		nodes, err = resolveSubscriptionContent(ctx, b, validateNode)
		if err == nil {
			if !persistToFile {
				return tag, nodes, nil
			}
			if err := ctx.Err(); err != nil {
				return "", nil, err
			}
			persistDir, openErr := openPersistDir(subscriptionDir, true)
			if openErr != nil {
				return "", nil, openErr
			}
			defer persistDir.Close()
			if err := persistSubscription(persistDir, tag+".sub", b); err != nil {
				return "", nil, err
			}
			if err := ctx.Err(); err != nil {
				return "", nil, err
			}
			return tag, nodes, nil
		}
	}
	if !persistToFile {
		if err != nil {
			return "", nil, fmt.Errorf("remote subscription is unusable: %w", err)
		}
		return "", nil, fmt.Errorf("remote subscription is unusable")
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", nil, ctxErr
	}

	log.Warnf("failed to use fresh subscription '%s'; trying cached copy", tag)
	freshErr := err
	persistDir, openErr := openPersistDir(subscriptionDir, false)
	if openErr != nil {
		return "", nil, fmt.Errorf("fresh subscription is unusable (%v); cached fallback is unavailable: %w", freshErr, openErr)
	}
	defer persistDir.Close()
	b, err = readPersistedSubscription(persistDir, tag+".sub")
	if err != nil {
		return "", nil, fmt.Errorf("fresh subscription is unusable (%v); cached fallback is unavailable: %w", freshErr, err)
	}
	nodes, err = resolveSubscriptionContent(ctx, b, validateNode)
	if err != nil {
		return "", nil, fmt.Errorf("fresh subscription is unusable (%v); cached fallback is unusable: %w", freshErr, err)
	}
	return tag, nodes, nil
}
