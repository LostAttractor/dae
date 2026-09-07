# QuickJS adapter

Surge uses a fork of [`buke/quickjs-go`](https://github.com/buke/quickjs-go) with
its bundled QuickJS-NG sources, pinned as the
[`third_party/quickjs-go`](../../../../../third_party/quickjs-go) Git submodule.
Binding fixes live in that repository; this directory applies Surge's primitive
host bridge and execution limits. Run `git submodule update --init --recursive`
before invoking Go commands directly.

Each invocation owns one runtime on a locked OS thread. Bare contexts disable
libc handlers, `std`, `os`, module loading and blocking Atomics operations.
The small Linux C helper caps the native stack to the current pthread's
available stack, including musl worker threads.
