# SPDX-License-Identifier: AGPL-3.0-only

# This directory builds independently of the dae source tree and Go toolchain.
DIST ?= dist

.PHONY: all clean test
all: node_modules/.installed clean
	node build.mjs "$(DIST)"

node_modules/.installed: package.json package-lock.json
	npm ci --no-audit --no-fund
	touch $@

clean:
	rm -rf "$(DIST)"

test: node_modules/.installed
	node tests/browser.mjs
