# SPDX-License-Identifier: AGPL-3.0-only

# Uses the repository's pnpm workspace without the daemon or Go toolchain.
DIST ?= dist

INPUTS := Makefile $(wildcard *.ts *.json .env*) \
	$(shell find src tooling tests -type f) \
	../package.json ../pnpm-lock.yaml ../pnpm-workspace.yaml ../node_modules/.modules.yaml

.PHONY: all clean deps dev test typecheck FORCE
all: ../build/web.stamp

FORCE:

../build/web.inputs: FORCE | deps
	@mkdir -p ../build
	@{ printf '%s\n' '$(abspath $(DIST))' "$$NODE_ENV"; command -v node; node --version; \
		printf '%s\n' $(INPUTS); } > $@.tmp
	@if ! cmp -s $@.tmp $@ || ! test -s ../build/web.outputs || \
		! (while IFS= read -r output; do test -f "$$output" || exit 1; done < ../build/web.outputs); then \
		mv $@.tmp $@; else rm $@.tmp; fi

../build/web.stamp: $(INPUTS) ../build/web.inputs
	pnpm run build "$(DIST)"
	@find "$(DIST)" -type f > ../build/web.outputs
	@touch $@

../node_modules/.modules.yaml: | deps
	@test -f $@

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
