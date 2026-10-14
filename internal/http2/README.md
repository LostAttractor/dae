# MITM HTTP/2 server

This package pins the HTTP/2 implementation from the official Go release named
in `upstream.json`. Only the MITM TCP listener uses its server. Outbound HTTP
clients and unrelated listeners continue to use `net/http`.

Generated files preserve the upstream BSD license. The manifest records each
source path and SHA-256 digest. `scripts/update-http2.py` copies production Go
files, redirects the two internal helper packages into this package, and uses
public `net/http` error values and content detection. Upstream test fixtures are
not imported. The public HPACK and HTTP header helpers use the project's pinned
`golang.org/x/net` dependency and are covered by the protocol integration tests.

The maintained differences are:

- `scripts/http2/request-metadata.patch` preserves `:scheme` in `Request.URL`
  and delivers validated, undeclared request trailers at EOF.
- `body_state.go` exposes `TryReadEOF() (bool, error)` on request bodies. It
  never waits for network input or consumes DATA. A successful result publishes
  final trailers and acknowledges EOF. `false, nil` means the request is not
  yet known to be exhausted; errors retain abnormal termination. The caller
  follows the same reader ownership rule as `Read`.
- `nethttp.go` adapts handlers, response writers, public server configuration,
  and graceful shutdown to `net/http`. Its connection registration prevents
  shutdown from missing a connection that is still being initialized.

The protocol parser retains its upstream validation and limits. The proxy
chooses HTTP/1 framing in `component/mitm/request_trailer.go`; that policy does
not belong in this package. EOF inspection adds no worker, timer, or body buffer.

## Updating the source

Install the intended official Go toolchain and obtain its source root:

```sh
GOTOOLCHAIN=go1.27.2 go env GOROOT
```

Pass the reported directory to the updater:

```sh
python3 scripts/update-http2.py --goroot /path/to/go
python3 scripts/update-http2.py --goroot /path/to/go --check
go test -race ./internal/http2/... ./component/mitm -count=1
```

The update fails when the patch no longer applies. Review the upstream changes
before adjusting the patch or the adapters, including request lifetimes,
trailer publication, shutdown, and flow-control accounting. Keep adjustments
separate from the generated source update so the maintained delta is reviewable.
Do not edit generated files directly.

The HTTP protocol CI job checks regeneration, the minimum supported Go compiler,
the latest stable compiler, proxy integration, and the QUIC submodule's own
tests. The MITM maintainer also follows Go HTTP/2 release and security notices;
upgrading the compiler alone does not update this pinned copy. When upstream
exposes equivalent request metadata, the local extensions can be removed while
retaining the protocol contract tests.
