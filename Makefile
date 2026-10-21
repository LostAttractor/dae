#
#  SPDX-License-Identifier: AGPL-3.0-only
#  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
#

# Host eBPF compiler: Clang 15+ recommended. CC selects the target cgo
# compiler; QuickJS on MIPS64 requires Clang 23+ when CC is Clang-based.
CLANG ?= clang
STRIP ?= llvm-strip
LLVM_OBJDUMP ?= llvm-objdump
CFLAGS := -O2 -Wall -Werror $(CFLAGS)
TARGET ?= bpfel,bpfeb
OUTPUT ?= dae
TEST_ARGS ?=
MAX_MATCH_SET_LEN ?= 1024
# Workload-sized tables; internal layout and metadata limits stay in tproxy.c.
MAX_DST_MAPPING_NUM ?= 262144
MAX_DST_MAPPING_NUM_UDP ?= 131072
MAX_UDP_ROUTING_CACHE_NUM ?= 65536
MAX_DOMAIN_ROUTING_NUM ?= 65536
BPF_CAPACITIES := MAX_MATCH_SET_LEN MAX_DST_MAPPING_NUM MAX_DST_MAPPING_NUM_UDP MAX_UDP_ROUTING_CACHE_NUM MAX_DOMAIN_ROUTING_NUM
BPF_CAPACITY_FLAGS := $(foreach name,$(BPF_CAPACITIES),-D$(name)=$($(name)))
BPF_GO_LDFLAGS := -X github.com/daeuniverse/dae/common/consts.MaxMatchSetLen_=$(MAX_MATCH_SET_LEN)
DEBUG_FLAGS ?= n
NOSTRIP ?= n
STATIC ?= n
GRPC_TRACE ?= n
SURGE_RUNTIME ?= quickjs
PLUGINS_CONFIG ?= plugins.cfg
ifeq ($(SURGE_RUNTIME),nodejs)
CGO_ENABLED ?= 0
else ifeq ($(SURGE_RUNTIME),quickjs)
CGO_ENABLED ?= 1
else
$(error SURGE_RUNTIME must be quickjs or nodejs)
endif
export CGO_ENABLED
GO_BUILD_TAGS := netgo,osusergo
ifeq ($(SURGE_RUNTIME),nodejs)
GO_BUILD_TAGS := $(GO_BUILD_TAGS),surge_nodejs
endif
ifneq ($(GRPC_TRACE),y)
GO_BUILD_TAGS := $(GO_BUILD_TAGS),grpcnotrace
endif
STRIP_PATH := $(shell command -v $(STRIP) 2>/dev/null)
BUILD_TAGS_FILE := .build_tags
ifneq ($(filter y,$(DEBUG_FLAGS) $(NOSTRIP)),)
	STRIP_FLAG := -no-strip
else ifeq ($(wildcard $(STRIP_PATH)),)
	STRIP_FLAG := -no-strip
else
	STRIP_FLAG := -strip=$(STRIP_PATH)
endif

GO_TRIMPATH_FLAG := -trimpath
GO_STRIP_FLAGS := -s -w
GO_DEBUG_FLAGS :=
ifeq ($(strip $(DEBUG_FLAGS)),y)
	GO_TRIMPATH_FLAG :=
	GO_STRIP_FLAGS :=
	GO_DEBUG_FLAGS := -gcflags="all=-N -l"
endif

GOARCH ?= $(shell go env GOARCH)
GO_VERSION ?= $(shell go env GOVERSION 2>/dev/null)
.DEFAULT_GOAL := dae

BIG_ENDIAN_GOARCHES := mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

# Get version from Git, including linked worktrees where .git is a file.
date=$(shell git log -1 --format="%cd" --date=short | sed s/-//g)
count=$(shell git rev-list --count HEAD)
commit=$(shell git rev-parse --short HEAD)
ifeq ($(shell test -e .git && git rev-parse --is-inside-work-tree 2>/dev/null),true)
	VERSION ?= unstable-$(date).r$(count).$(commit)
else
	VERSION ?= unstable-0.nogit
endif

ifeq ($(STATIC),y)
ifeq ($(CGO_ENABLED),1)
STATIC_LDFLAGS := -linkmode=external -extldflags '-static -Wl,-z,stack-size=2097152'
endif
endif
BUILD_ARGS := $(GO_TRIMPATH_FLAG) $(GO_DEBUG_FLAGS) -ldflags "$(GO_STRIP_FLAGS) -X github.com/daeuniverse/dae/cmd.Version=$(VERSION) $(BPF_GO_LDFLAGS) $(STATIC_LDFLAGS)" $(BUILD_ARGS)

.PHONY: check-go-arch check-go-version check-bpf-capacities clean-ebpf dae ebpf ebpf-audit ebpf-lint ebpf-test ebpf-test-build fmt plugins submodule submodules test

check-bpf-capacities:
	@for entry in $(foreach name,$(BPF_CAPACITIES),'$(name)=$($(name))'); do \
		value=$${entry#*=}; \
		case "$$value" in ''|0*|*[!0-9]*) echo "ERROR: $$entry must be a positive decimal integer without leading zeros" >&2; exit 1 ;; esac; \
		if [ "$$value" -eq 0 ] || [ "$$value" -gt 4294967294 ]; then echo "ERROR: invalid capacity $$entry" >&2; exit 1; fi; \
	done
	@if [ "$(MAX_MATCH_SET_LEN)" -lt 32 ] || [ "$(MAX_MATCH_SET_LEN)" -gt 65536 ] || [ $$(( $(MAX_MATCH_SET_LEN) % 32 )) -ne 0 ]; then \
		echo "ERROR: MAX_MATCH_SET_LEN must be a multiple of 32 in [32, 65536]" >&2; exit 1; \
	fi

check-go-arch:
	@if [ -n "$(filter $(GOARCH),$(BIG_ENDIAN_GOARCHES))" ]; then \
		echo "ERROR: dae does not support big-endian GOARCH=$(GOARCH); use a little-endian target." >&2; \
		exit 1; \
	fi

check-go-version:
	@version='$(GO_VERSION)'; \
	case "$$version" in \
		devel\ go*) version=$${version#devel }; version=$${version%%-*} ;; \
		go*) ;; \
		*) echo "ERROR: unable to determine the Go version (found '$$version')." >&2; exit 1 ;; \
	esac; \
	version=$${version#go}; \
	major=$${version%%.*}; \
	rest=$${version#*.}; \
	if [ "$$rest" = "$$version" ]; then \
		minor=0; patch=0; \
	else \
		minor=$${rest%%.*}; \
		if [ "$$minor" = "$$rest" ]; then \
			patch=0; \
		else \
			patch=$${rest#*.}; patch=$${patch%%[!0-9]*}; patch=$${patch:-0}; \
		fi; \
	fi; \
	case "$$major.$$minor.$$patch" in *[!0-9.]*) \
		echo "ERROR: unsupported Go version format '$(GO_VERSION)'." >&2; exit 1 ;; \
	esac; \
	supported=0; \
	if [ "$$major" -gt 1 ]; then \
		supported=1; \
	elif [ "$$major" -eq 1 ]; then \
		if [ "$$minor" -gt 27 ] || { [ "$$minor" -eq 27 ] && [ "$$patch" -ge 2 ]; }; then \
			supported=1; \
		fi; \
	fi; \
	if [ "$$supported" -ne 1 ]; then \
		echo "ERROR: Go 1.27.2+ is required (found $(GO_VERSION))." >&2; \
		exit 1; \
	fi

## Begin Dae Build
dae: export GOOS=linux
dae: check-go-arch check-go-version plugins ebpf web-assets
	@echo $(CFLAGS)
	go build -tags=$(GO_BUILD_TAGS),$(shell cat $(BUILD_TAGS_FILE)) -o $(OUTPUT) $(BUILD_ARGS) .
## End Dae Build

# Refresh even after removing a plugin; run the generator on the build host.
plugins: check-go-version
	@unset GOOS GOARCH GOARM GOARM64 GOAMD64 GO386 GOMIPS GOMIPS64 GOPPC64 GORISCV64; \
	GOWORK=off CGO_ENABLED=0 go run ./cmd/dae-plugin-gen -config="$(PLUGINS_CONFIG)"

## Begin Git Submodules
SUBMODULE_PATHS := $(shell sed -n 's/^[[:space:]]*path[[:space:]]*=[[:space:]]*//p' .gitmodules)
ifeq ($(SURGE_RUNTIME),nodejs)
SUBMODULE_PATHS := $(filter-out third_party/quickjs-go,$(SUBMODULE_PATHS))
endif
MISSING_SUBMODULE_PATHS := $(foreach path,$(SUBMODULE_PATHS),$(if $(wildcard $(path)/*),,$(path)))

submodule submodules:
ifneq ($(strip $(MISSING_SUBMODULE_PATHS)),)
	git submodule update --init --recursive -- $(MISSING_SUBMODULE_PATHS)
endif
## End Git Submodules

## Begin Ebpf
.PHONY: FORCE
FORCE:

BPF_INPUTS := Makefile go.mod go.sum control/control.go trace/trace.go \
	$(shell find control/kern trace/kern kern -type f \( -name '*.c' -o -name '*.h' \) ! -path 'control/kern/tests/*') \
	$(filter-out %_test.go,$(wildcard cmd/dae-bpf-pack/*.go cmd/dae-routing-abi/*.go))

.PHONY: clean-ebpf-production clean-ebpf-test
clean-ebpf: clean-ebpf-production clean-ebpf-test

clean-ebpf-production:
	@rm -f $(BUILD_TAGS_FILE)
	@rm -f control/bpf*bpf*.go && \
		rm -f control/bpf*bpf*.o control/bpf*bpf*.o.gz
	@rm -f trace/bpf_*bpf*.go && \
		rm -f trace/bpf_*bpf*.o trace/bpf_*bpf*.o.gz

clean-ebpf-test:
	@rm -f control/kern/tests/bpftest_*bpf*.go && \
		rm -f control/kern/tests/bpftest_*bpf*.o
fmt: check-go-version submodule web-assets
	go fmt ./...

# $BPF_CLANG is used in go:generate invocations.
ebpf: export BPF_CLANG := $(CLANG)
ebpf: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf: export BPF_CFLAGS := $(BPF_CAPACITY_FLAGS) $(CFLAGS)
ebpf: export BPF_TARGET := $(TARGET)
ebpf: export BPF_TRACE_TARGET = $(GOARCH)
# bpf2go uses -mod=mod, so generate BPF from dae's pinned module outside any
# plugin workspace. The final Go build still uses the caller's workspace.
ebpf: $(BUILD_TAGS_FILE)

# Keep Make's timestamp dependencies, including changes to the input list and
# compiler options. A missing output invalidates the complete generated set.
build/ebpf.inputs: FORCE | submodule
	@mkdir -p build
	@{ printf '%s\n' '$(GO_VERSION)' "$$BPF_CFLAGS" "$$BPF_TARGET" "$$BPF_TRACE_TARGET" "$$BPF_STRIP_FLAG"; \
		command -v go; command -v "$$BPF_CLANG"; "$$BPF_CLANG" --version; \
		$(if $(STRIP_PATH),"$(STRIP_PATH)" --version;) \
		printf '%s\n' $(BPF_INPUTS); } > $@.tmp
	@if ! cmp -s $@.tmp $@ || ! test -s build/ebpf.outputs || \
		! (while IFS= read -r output; do test -f "$$output" || exit 1; done < build/ebpf.outputs); then \
		mv $@.tmp $@; else rm $@.tmp; fi

$(BUILD_TAGS_FILE): $(BPF_INPUTS) build/ebpf.inputs | check-go-version check-bpf-capacities
	$(MAKE) clean-ebpf-production
	@unset GOOS && \
	unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    GOWORK=off CGO_ENABLED=0 go generate ./control/control.go && \
	tags='' && \
	case "$(GOARCH)" in \
		amd64|arm64|riscv64|loong64|ppc64|ppc64le) \
			GOWORK=off CGO_ENABLED=0 go generate ./trace/trace.go && tags=trace ;; \
		*) echo "trace disabled on $(GOARCH): BPF probe argument ABI is unsupported" ;; \
	esac && \
	printf '%s\n' "$$tags" > $(BUILD_TAGS_FILE) && \
	for output in $(BUILD_TAGS_FILE) internal/routingabi/abi_generated.go \
		control/bpf*_bpf*.go control/bpf*_bpf*.o control/bpf*_bpf*.o.gz \
		trace/bpf_*bpf*.go trace/bpf_*bpf*.o trace/bpf_*bpf*.o.gz; do \
		test ! -f "$$output" || printf '%s\n' "$$output"; \
	done > build/ebpf.outputs

test: plugins ebpf web-assets
	go test $(GO_DEBUG_FLAGS) $(TEST_ARGS) -ldflags "$(BPF_GO_LDFLAGS)" -tags=$(GO_BUILD_TAGS),$(shell cat $(BUILD_TAGS_FILE)) ./...
	$(MAKE) check-boundaries

.PHONY: config-parser config-parser-check check-boundaries
config-parser: check-go-version
	python3 scripts/generate-config-parser.py

config-parser-check: check-go-version
	python3 scripts/generate-config-parser.py --check

# Package boundaries remain independent of the repository's module boundary.
check-boundaries: check-go-version
	@dependencies=$$(CGO_ENABLED=0 go list -deps ./pkg/outbound/...) && \
		printf '%s\n' "$$dependencies" | \
		awk '/^github.com\/daeuniverse\/dae\// && !/^github.com\/daeuniverse\/dae\/pkg\/(outbound|proxylink)(\/|$$)/ { print "Forbidden outbound dependency: " $$0; bad=1 } END { exit bad }'
	@dependencies=$$(CGO_ENABLED=0 go list -deps ./component/plugin/... ./component/pluginhost/... ./component/mitm ./control) && \
		printf '%s\n' "$$dependencies" | \
		awk '/^github.com\/daeuniverse\/dae\/plugins\// { print "Forbidden host dependency: " $$0; bad=1 } END { exit bad }'

ebpf-lint:
	./scripts/checkpatch.pl --no-tree --strict --no-summary --show-types --color=always control/kern/tproxy.c $(wildcard control/kern/*.h kern/*.h) --ignore COMMIT_COMMENT_SYMBOL,NOT_UNIFIED_DIFF,COMMIT_LOG_LONG_LINE,LONG_LINE_COMMENT,VOLATILE,ASSIGN_IN_IF,PREFER_DEFINED_ATTRIBUTE_MACRO,CAMELCASE,LEADING_SPACE,OPEN_ENDED_LINE,SPACING,BLOCK_COMMENT_STYLE

ebpf-test-build: export BPF_CLANG := $(CLANG)
ebpf-test-build: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf-test-build: export BPF_CFLAGS := $(BPF_CAPACITY_FLAGS) $(CFLAGS)
ebpf-test-build: export BPF_TARGET := $(TARGET)
ebpf-test-build: export BPF_TRACE_TARGET = $(GOARCH)
ebpf-test-build: check-go-version check-bpf-capacities submodule clean-ebpf-test
	@goos=$$(go env GOOS); \
	if [ "$$goos" != "linux" ]; then \
		echo "ERROR: eBPF tests require Linux (found $$goos)." >&2; \
		exit 1; \
	fi; \
	unset GOOS && \
    unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    GOWORK=off go generate ./control/kern/tests/bpf_test.go && \
    mkdir -p build/ebpf-test && \
    CGO_ENABLED=0 go test $(GO_DEBUG_FLAGS) -c -ldflags "$(BPF_GO_LDFLAGS)" -tags dae_bpf_tests -o build/ebpf-test/kernel.test ./control/kern/tests

ebpf-test: ebpf-test-build
	./build/ebpf-test/kernel.test -test.v -test.timeout=10m

ebpf-audit: check-go-version check-bpf-capacities
	CLANG="$(CLANG)" LLVM_OBJDUMP="$(LLVM_OBJDUMP)" BPF_CAPACITY_FLAGS="$(BPF_CAPACITY_FLAGS)" MAX_MATCH_SET_LEN="$(MAX_MATCH_SET_LEN)" ./scripts/ebpf-audit.sh

## End Ebpf

# API consumers build without native runtime dependencies or eBPF generation.
CLIENT_OUTPUT ?= dae-client
WEB_OUTPUT ?= build/web
.PHONY: client web web-assets client-test
client: check-go-version
	CGO_ENABLED=0 go build $(GO_TRIMPATH_FLAG) $(GO_DEBUG_FLAGS) -o $(CLIENT_OUTPUT) ./cmd/dae-client

web:
	$(MAKE) -C web DIST="$(abspath $(WEB_OUTPUT))"

# Only frontend build output crosses into the daemon's Go package.
web-assets: web
	@if ! diff -qr "$(WEB_OUTPUT)" internal/webui/assets >/dev/null 2>&1; then \
		rm -rf internal/webui/assets && mkdir -p internal/webui/assets && \
		cp -R "$(WEB_OUTPUT)/." internal/webui/assets/; \
	fi

client-test: check-go-version
	@dependencies=$$(CGO_ENABLED=0 go list -deps ./api/... ./client/...) && \
		printf '%s\n' "$$dependencies" | \
		awk '/^github.com\/daeuniverse\/dae\/component\// { print "Forbidden core client dependency: " $$0; bad=1 } END { exit bad }'
	CGO_ENABLED=0 go test $(GO_DEBUG_FLAGS) ./api/... ./client/... ./plugins/surge/api ./plugins/surge/client ./cmd/dae-client
	@dependencies=$$(CGO_ENABLED=0 go list -deps ./api/... ./client/... ./plugins/surge/api ./plugins/surge/client ./cmd/dae-client) && \
		printf '%s\n' "$$dependencies" | \
		awk '/^github.com\/daeuniverse\/dae\// && !/^github.com\/daeuniverse\/dae\/(api|client)\// && $$0 != "github.com/daeuniverse/dae/api" && $$0 != "github.com/daeuniverse/dae/cmd/dae-client" && $$0 != "github.com/daeuniverse/dae/pkg/clitable" && $$0 != "github.com/daeuniverse/dae/pkg/terminaltext" && $$0 != "github.com/daeuniverse/dae/plugins/surge/api" && $$0 != "github.com/daeuniverse/dae/plugins/surge/client" { print "Forbidden client dependency: " $$0; bad=1 } END { exit bad }'
