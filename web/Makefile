# SPDX-License-Identifier: AGPL-3.0-only

# Uses the repository's pnpm workspace without the daemon or Go toolchain.
DIST ?= dist

.PHONY: all clean deps dev test typecheck
all: deps clean
	pnpm run build "$(DIST)"

deps:
	pnpm install --frozen-lockfile

clean:
	rm -rf "$(DIST)"

dev: deps
	pnpm run dev

test: deps
	pnpm run types:check
	pnpm run typecheck
	pnpm run test:dev
	pnpm test

typecheck: deps
	pnpm run typecheck
