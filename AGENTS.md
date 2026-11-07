# AGENTS.md

## Setup

- Initialize submodules in every clone and worktree: `git submodule update --init --recursive`.
- Enter the development environment with `direnv allow` or `nix-shell`. Without Nix, install Go 1.27.2+, Clang/LLVM with the BPF backend, and Node.js 22.13+, then run `corepack enable pnpm`.
- Run `pnpm install` (`make` also runs it) to install dependencies and the husky Git hooks. Worktrees created with `git worktree add` from a set-up clone receive the hooks immediately.

## Development Workflow

- Change unreleased features directly; skip backward compatibility and migration code or docs.
- Reuse existing Prometheus metrics and underlying statistics. Share data sources across `status`, `--recent`, and other views to avoid double counting and inconsistent semantics.
- Keep all first-party Go code in the root `go.mod`. Update every first-party plugin under `plugins/` when changing plugin APIs. External plugins use `plugins.cfg` / `go.work`.
- Use minimal, self-written test fixtures. Do not add third-party test scripts, modules, or blobs without permission.
- After changing `go.mod`, `go.sum`, or `pnpm-lock.yaml`, run `nix/update-hashes.sh` and commit the refreshed `nix/package.nix` hashes with the dependency change. The `.husky/pre-commit` hook, installed by `pnpm install`, does this.

## Design Goal

Use eBPF to minimize userspace work. Send only proxy traffic and traffic requiring userspace handling, such as DNS and MITM, to userspace, with explicit rules defining the scope.
