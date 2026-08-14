#
#  SPDX-License-Identifier: AGPL-3.0-only
#  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
#

# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang
STRIP ?= llvm-strip
LLVM_OBJDUMP ?= llvm-objdump
CFLAGS := -O2 -Wall -Werror $(CFLAGS)
TARGET ?= bpfel,bpfeb
OUTPUT ?= dae
MAX_MATCH_SET_LEN ?= 1024
CFLAGS := -DMAX_MATCH_SET_LEN=$(MAX_MATCH_SET_LEN) $(CFLAGS)
NOSTRIP ?= n
STRIP_PATH := $(shell command -v $(STRIP) 2>/dev/null)
BUILD_TAGS_FILE := .build_tags
ifeq ($(strip $(NOSTRIP)),y)
	STRIP_FLAG := -no-strip
else ifeq ($(wildcard $(STRIP_PATH)),)
	STRIP_FLAG := -no-strip
else
	STRIP_FLAG := -strip=$(STRIP_PATH)
endif

GOARCH ?= $(shell go env GOARCH)
GO_VERSION ?= $(shell go env GOVERSION 2>/dev/null)
.DEFAULT_GOAL := dae

BIG_ENDIAN_GOARCHES := mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

# Do NOT remove the line below. This line is for CI.
#export GOMODCACHE=$(PWD)/go-mod

# Get version from Git, including linked worktrees where .git is a file.
date=$(shell git log -1 --format="%cd" --date=short | sed s/-//g)
count=$(shell git rev-list --count HEAD)
commit=$(shell git rev-parse --short HEAD)
ifeq ($(shell git rev-parse --is-inside-work-tree 2>/dev/null),true)
	VERSION ?= unstable-$(date).r$(count).$(commit)
else
	VERSION ?= unstable-0.nogit
endif

BUILD_ARGS := -trimpath -ldflags "-s -w -X github.com/daeuniverse/dae/cmd.Version=$(VERSION) -X github.com/daeuniverse/dae/common/consts.MaxMatchSetLen_=$(MAX_MATCH_SET_LEN)" $(BUILD_ARGS)

.PHONY: check-go-arch check-go-version clean-ebpf dae ebpf ebpf-audit ebpf-lint ebpf-test fmt submodule submodules test

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
		if [ "$$minor" -gt 25 ]; then \
			supported=1; \
		elif [ "$$minor" -eq 25 ] && [ "$$patch" -ge 7 ]; then \
			supported=1; \
		elif [ "$$minor" -eq 24 ] && [ "$$patch" -ge 13 ]; then \
			supported=1; \
		fi; \
	fi; \
	if [ "$$supported" -ne 1 ]; then \
		echo "ERROR: Go 1.24.13+, Go 1.25.7+, or Go 1.26+ is required (found $(GO_VERSION))." >&2; \
		echo "Older releases lack crypto/tls session resumption hardening related to golang/go#77217." >&2; \
		exit 1; \
	fi

## Begin Dae Build
dae: export GOOS=linux
ifndef CGO_ENABLED
dae: export CGO_ENABLED=0
endif
dae: check-go-arch check-go-version ebpf
	@echo $(CFLAGS)
	go build -tags=$(shell cat $(BUILD_TAGS_FILE)) -o $(OUTPUT) $(BUILD_ARGS) .
## End Dae Build

## Begin Git Submodules
SUBMODULE_PATHS := $(shell sed -n 's/^[[:space:]]*path[[:space:]]*=[[:space:]]*//p' .gitmodules)
MISSING_SUBMODULE_PATHS := $(foreach path,$(SUBMODULE_PATHS),$(if $(wildcard $(path)/*),,$(path)))

submodule submodules:
ifneq ($(strip $(MISSING_SUBMODULE_PATHS)),)
	git submodule update --init --recursive -- $(MISSING_SUBMODULE_PATHS)
endif
## End Git Submodules

## Begin Ebpf
clean-ebpf:
	@rm -f $(BUILD_TAGS_FILE)
	@rm -f control/bpf_*bpf*.go && \
		rm -f control/bpf_*bpf*.o
	@rm -f control/internal/splice/bpf_*bpf*.go && \
		rm -f control/internal/splice/bpf_*bpf*.o
	@rm -f trace/bpf_*bpf*.go && \
		rm -f trace/bpf_*bpf*.o
	@rm -f control/kern/tests/bpftest_*bpf*.go && \
		rm -f control/kern/tests/bpftest_*bpf*.o
fmt: check-go-version
	go fmt ./...

# $BPF_CLANG is used in go:generate invocations.
ebpf: export BPF_CLANG := $(CLANG)
ebpf: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf: export BPF_CFLAGS := $(CFLAGS)
ebpf: export BPF_TARGET := $(TARGET)
ebpf: export BPF_TRACE_TARGET := $(GOARCH)
ebpf: check-go-version submodule clean-ebpf
	@unset GOOS && \
	unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    go generate ./control/control.go && \
	tags='' && \
	case "$(GOARCH)" in \
		amd64|arm64|riscv64|loong64|ppc64|ppc64le) \
			go generate ./trace/trace.go && tags=trace ;; \
		*) echo "trace disabled on $(GOARCH): BPF probe argument ABI is unsupported" ;; \
	esac && \
	go generate ./control/internal/splice/generate.go && \
	if [ -n "$$tags" ]; then tags="$$tags,dae_splice"; else tags=dae_splice; fi && \
	printf '%s\n' "$$tags" > $(BUILD_TAGS_FILE)

test: ebpf
	go test -tags=$(shell cat $(BUILD_TAGS_FILE)) ./...

ebpf-lint:
	./scripts/checkpatch.pl --no-tree --strict --no-summary --show-types --color=always control/internal/splice/kern/splice.c --ignore COMMIT_COMMENT_SYMBOL,NOT_UNIFIED_DIFF,COMMIT_LOG_LONG_LINE,LONG_LINE_COMMENT,VOLATILE,ASSIGN_IN_IF,PREFER_DEFINED_ATTRIBUTE_MACRO,CAMELCASE,LEADING_SPACE,OPEN_ENDED_LINE,SPACING,BLOCK_COMMENT_STYLE
	./scripts/checkpatch.pl --no-tree --strict --no-summary --show-types --color=always control/kern/tproxy.c --ignore COMMIT_COMMENT_SYMBOL,NOT_UNIFIED_DIFF,COMMIT_LOG_LONG_LINE,LONG_LINE_COMMENT,VOLATILE,ASSIGN_IN_IF,PREFER_DEFINED_ATTRIBUTE_MACRO,CAMELCASE,LEADING_SPACE,OPEN_ENDED_LINE,SPACING,BLOCK_COMMENT_STYLE

ebpf-test: export BPF_CLANG := $(CLANG)
ebpf-test: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf-test: export BPF_CFLAGS := $(CFLAGS)
ebpf-test: export BPF_TARGET := $(TARGET)
ebpf-test: export BPF_TRACE_TARGET := $(GOARCH)
ebpf-test: check-go-version submodule clean-ebpf
	@goos=$$(go env GOOS); \
	if [ "$$goos" != "linux" ]; then \
		echo "ERROR: eBPF tests require Linux (found $$goos)." >&2; \
		exit 1; \
	fi; \
	unset GOOS && \
    unset GOARCH && \
    unset GOARM && \
    echo $(STRIP_FLAG) && \
    go generate ./control/kern/tests/bpf_test.go && \
    go clean -testcache && \
    go test -v -tags dae_bpf_tests ./control/kern/tests/...

ebpf-audit: check-go-version
	CLANG="$(CLANG)" LLVM_OBJDUMP="$(LLVM_OBJDUMP)" MAX_MATCH_SET_LEN="$(MAX_MATCH_SET_LEN)" ./scripts/ebpf-audit.sh

## End Ebpf
