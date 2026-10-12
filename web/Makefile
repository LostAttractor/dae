# SPDX-License-Identifier: AGPL-3.0-only

# This directory builds independently of the dae source tree and Go toolchain.
DIST ?= dist

.PHONY: all clean dev test typecheck
all: node_modules/.installed clean
	npm run build -- "$(DIST)"

node_modules/.installed: package.json package-lock.json
	npm ci --no-audit --no-fund
	touch $@

clean:
	rm -rf "$(DIST)"

dev: node_modules/.installed
	npm run dev

test: node_modules/.installed
	npm run types:check
	npm run typecheck
	npm run test:dev
	npm test

typecheck: node_modules/.installed
	npm run typecheck
