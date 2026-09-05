package surgemodule

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"golang.org/x/net/idna"
)

// URL support covers the network URL operations used by Surge scripts. Parsing
// and resolving are delegated to Go; scripts cannot use URL objects to gain any
// capability beyond the HTTP client already exposed to them.
func runtimeURL(operation, raw, key, value string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if operation == "parse" && key != "" {
		base, err := url.Parse(key)
		if err != nil || !base.IsAbs() {
			return "", errors.New("invalid base URL")
		}
		u = base.ResolveReference(u)
	}
	if !u.IsAbs() {
		return "", errors.New("URL must be absolute or have an absolute base")
	}
	if operation == "set" {
		switch key {
		case "hostname":
			name := strings.Trim(value, "[]")
			if strings.ContainsAny(name, "/?#@\\ \t\r\n") || name == "" {
				return "", errors.New("invalid URL hostname")
			}
			if port := u.Port(); port != "" {
				u.Host = net.JoinHostPort(name, port)
			} else if strings.Contains(name, ":") {
				u.Host = "[" + name + "]"
			} else {
				u.Host = name
			}
		case "search":
			u.RawQuery, u.ForceQuery = strings.TrimPrefix(value, "?"), value == "?"
		case "hash":
			u.Fragment, u.RawFragment = strings.TrimPrefix(value, "#"), ""
		case "pathname":
			u.Path, u.RawPath = value, ""
			if !strings.HasPrefix(u.Path, "/") {
				u.Path = "/" + u.Path
			}
		default:
			return "", fmt.Errorf("URL setter %q is not supported", key)
		}
	} else if operation != "parse" {
		return "", errors.New("unknown URL operation")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	networkURL := u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "ws" || u.Scheme == "wss"
	if networkURL {
		if u.Host == "" || strings.ContainsAny(u.Host, "\\ \t\r\n") {
			return "", errors.New("invalid URL host")
		}
		name := strings.ToLower(u.Hostname())
		if !strings.Contains(name, ":") {
			name, err = idna.Lookup.ToASCII(name)
			if err != nil {
				return "", err
			}
		}
		port := u.Port()
		if port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 0 || n > 65535 {
				return "", errors.New("invalid URL port")
			}
			if (u.Scheme == "https" || u.Scheme == "wss") && n == 443 || (u.Scheme == "http" || u.Scheme == "ws") && n == 80 {
				port = ""
			}
		}
		if port != "" {
			u.Host = net.JoinHostPort(name, port)
		} else if strings.Contains(name, ":") {
			u.Host = "[" + name + "]"
		} else {
			u.Host = name
		}
		if u.Path == "" {
			u.Path = "/"
		}
	}
	search, fragment, origin := "", "", "null"
	if u.RawQuery != "" || u.ForceQuery {
		search = "?" + u.RawQuery
	}
	if u.Fragment != "" {
		fragment = "#" + u.EscapedFragment()
	}
	if networkURL {
		origin = u.Scheme + "://" + u.Host
	}
	hostname := u.Hostname()
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	data, err := json.Marshal(map[string]string{
		"href": u.String(), "protocol": u.Scheme + ":", "host": u.Host, "hostname": hostname,
		"port": u.Port(), "pathname": u.EscapedPath(), "search": search, "hash": fragment, "origin": origin,
	})
	return string(data), err
}

func runtimeUngzip(ctx context.Context, encoded string, limit int64) (string, error) {
	if int64(base64.StdEncoding.DecodedLen(len(encoded))) > limit+2 {
		return "", errors.New("$utils.ungzip input exceeds body limit")
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	zr, err := gzip.NewReader(common.NewContextReader(ctx, bytes.NewReader(data)))
	if err != nil {
		return "", fmt.Errorf("$utils.ungzip: %w", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(common.NewContextReader(ctx, zr), limit+1))
	if err != nil {
		return "", fmt.Errorf("$utils.ungzip: %w", err)
	}
	if int64(len(out)) > limit {
		return "", errors.New("$utils.ungzip output exceeds body limit")
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

// This inert HTML tree implements only the DOM operations needed by Sparkle's
// webpage filter. It never executes page scripts, loads resources, or exposes
// browser/process globals. Both total text allocation and nodes are bounded.
type runtimeDOM struct {
	ctx       context.Context
	limit     int64
	allocated int64
	nodes     []*html.Node
	ids       map[*html.Node]int
}

func newRuntimeDOM(ctx context.Context, limit int64) *runtimeDOM {
	return &runtimeDOM{ctx: ctx, limit: limit, nodes: []*html.Node{nil}, ids: make(map[*html.Node]int)}
}

const runtimeDOMMaxNodes = 32768

func (d *runtimeDOM) remember(n *html.Node) int {
	if n == nil {
		return 0
	}
	if id := d.ids[n]; id != 0 {
		return id
	}
	id := len(d.nodes)
	d.ids[n] = id
	d.nodes = append(d.nodes, n)
	return id
}

func (d *runtimeDOM) call(op, first, second string) (any, error) {
	if err := d.ctx.Err(); err != nil {
		return nil, err
	}
	if op == "parse" {
		if int64(len(first))+d.allocated > d.limit {
			return nil, errors.New("DOMParser HTML exceeds body limit")
		}
		// Bound token count before constructing the tree, rather than allowing
		// a tiny-tags input to create an unbounded host-side DOM allocation.
		z := html.NewTokenizer(strings.NewReader(first))
		z.SetMaxBuf(int(d.limit))
		count := len(d.nodes)
		for z.Next() != html.ErrorToken {
			count++
			if count > runtimeDOMMaxNodes/2 {
				return nil, errors.New("DOMParser node limit exceeded")
			}
			if err := d.ctx.Err(); err != nil {
				return nil, err
			}
		}
		if err := z.Err(); err != io.EOF {
			return nil, err
		}
		doc, err := html.Parse(common.NewContextReader(d.ctx, strings.NewReader(first)))
		if err != nil {
			return nil, err
		}
		d.allocated += int64(len(first))
		stack := []*html.Node{doc}
		for len(stack) > 0 {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if len(d.nodes) >= runtimeDOMMaxNodes {
				return nil, errors.New("DOMParser node limit exceeded")
			}
			d.remember(n)
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				stack = append(stack, c)
			}
		}
		return strconv.Itoa(d.ids[doc]), nil
	}
	if op == "create" {
		if len(d.nodes) >= runtimeDOMMaxNodes {
			return nil, errors.New("DOMParser node limit exceeded")
		}
		name := strings.ToLower(first)
		if name != "script" && name != "style" {
			return nil, errors.New("DOMParser createElement supports script and style elements only")
		}
		return strconv.Itoa(d.remember(&html.Node{Type: html.ElementNode, Data: name, DataAtom: atom.Lookup([]byte(name))})), nil
	}
	id, err := strconv.Atoi(first)
	if err != nil || id <= 0 || id >= len(d.nodes) {
		return nil, errors.New("invalid DOM node")
	}
	n := d.nodes[id]
	switch op {
	case "documentElement", "head", "body":
		name := op
		if name == "documentElement" {
			name = "html"
		}
		stack := []*html.Node{n}
		for len(stack) > 0 {
			current := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if current.Type == html.ElementNode && current.Data == name {
				return strconv.Itoa(d.remember(current)), nil
			}
			for c := current.LastChild; c != nil; c = c.PrevSibling {
				stack = append(stack, c)
			}
		}
		return "0", nil
	case "textContent":
		if n.Type != html.ElementNode || (n.Data != "script" && n.Data != "style") {
			return nil, errors.New("DOMParser textContent setter supports script and style elements only")
		}
		if d.allocated+int64(len(second)) > d.limit || len(d.nodes) >= runtimeDOMMaxNodes {
			return nil, errors.New("DOMParser allocation limit exceeded")
		}
		for n.FirstChild != nil {
			n.RemoveChild(n.FirstChild)
		}
		child := &html.Node{Type: html.TextNode, Data: second}
		n.AppendChild(child)
		d.remember(child)
		d.allocated += int64(len(second))
		return nil, nil
	case "appendChild":
		childID, err := strconv.Atoi(second)
		if err != nil || childID <= 0 || childID >= len(d.nodes) {
			return nil, errors.New("invalid child node")
		}
		child := d.nodes[childID]
		if n.Type != html.ElementNode || child.Type != html.ElementNode || (child.Data != "script" && child.Data != "style") {
			return nil, errors.New("DOMParser appendChild supports script and style elements only")
		}
		for parent := n; parent != nil; parent = parent.Parent {
			if parent == child {
				return nil, errors.New("DOMParser cannot create a node cycle")
			}
		}
		if child.Parent != nil {
			child.Parent.RemoveChild(child)
		}
		n.AppendChild(child)
		return nil, nil
	case "outerHTML":
		w := &runtimeDOMWriter{ctx: d.ctx, limit: d.limit}
		if err := html.Render(w, n); err != nil {
			return nil, err
		}
		return w.content.String(), nil
	default:
		return nil, fmt.Errorf("DOMParser operation %q is not supported", op)
	}
}

type runtimeDOMWriter struct {
	content strings.Builder
	ctx     context.Context
	limit   int64
}

func (w *runtimeDOMWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(w.content.Len()+len(p)) > w.limit {
		return 0, errors.New("DOMParser output exceeds body limit")
	}
	return w.content.Write(p)
}
