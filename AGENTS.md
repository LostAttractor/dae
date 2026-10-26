# AGENTS.md

## Development Workflow

- Change unreleased features directly; skip backward compatibility and migration code or docs.
- Reuse existing Prometheus metrics and underlying statistics. Share data sources across `status`, `--recent`, and other views to avoid double counting and inconsistent semantics.
- Keep all first-party Go code in the root `go.mod`. Update every first-party plugin under `plugins/` when changing plugin APIs. External plugins use `plugins.cfg` / `go.work`.
- Use minimal, self-written test fixtures. Do not add third-party test scripts, modules, or blobs without permission.

## Design Goal

Use eBPF to minimize userspace work. Send only proxy traffic and traffic requiring userspace handling, such as DNS and MITM, to userspace, with explicit rules defining the scope.
