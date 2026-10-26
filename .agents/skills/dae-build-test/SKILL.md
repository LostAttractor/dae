---
name: dae-build-test
description: Build and test dae, select first-party plugins and Surge runtimes for coverage, run Web/frontend tests, or regenerate the config parser after grammar changes.
---

# dae Build and Test

Enter the development environment with `direnv` or `nix-shell` at the repository root.

## Build and eBPF

- `make` builds Go, eBPF, and Web assets into `./dae`. See the root `Makefile` for other targets and variables.
- Run `git submodule update --init --recursive` if kernel headers are missing. `make ebpf` also initializes missing submodules.
- Run `make ebpf-lint` after eBPF C changes. `make ebpf-test-build` only compiles tests; `make ebpf-test` runs kernel tests and requires root.

## Go, Plugins, and Runtimes

- Test affected Go packages first. For concurrency, connection, or resource lifecycle changes, also run their tests with `-race`, preserving required build tags and CGO settings.
- For temporary plugin selections, create a config from `plugins.cfg.example` and pass `make test PLUGINS_CONFIG=/path/to/temp/plugins.cfg`. Enable the example's optional plugins to cover all first-party plugins.
- Run `make test SURGE_RUNTIME=nodejs` to verify the Node backend without CGO. Pass `PLUGINS_CONFIG` too when using a temporary plugin selection.
- Run `make check-boundaries` after package dependency or plugin boundary changes, and `make client-test` for API or client changes. `make test` already includes `check-boundaries`.

## Web

Run `make -C web test` with Chromium installed after frontend changes to check API type consistency, TypeScript, the dev server, and frontend tests.

## Config Parser

After changing `pkg/config_parser/grammar/dae_config.g4`, run `make config-parser` and commit the generated code. Run `make config-parser-check` to verify grammar and generator version consistency.
