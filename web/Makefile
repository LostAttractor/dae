# SPDX-License-Identifier: AGPL-3.0-only

# This directory builds independently of the dae source tree and Go toolchain.
DIST ?= dist

.PHONY: all clean test
all: clean
	mkdir -p "$(DIST)"
	cp -R src/. "$(DIST)/"

clean:
	rm -rf "$(DIST)"

test:
	node tests/browser.mjs
