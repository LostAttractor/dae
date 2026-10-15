FROM --platform=$BUILDPLATFORM golang:1.27.2 AS go-toolchain
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS node-toolchain

FROM --platform=$BUILDPLATFORM ubuntu:24.04 AS builder
COPY --from=go-toolchain /usr/local/go /usr/local/go
COPY --from=node-toolchain /usr/local/bin/node /usr/local/bin/node
COPY --from=node-toolchain /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/corepack/dist/corepack.js /usr/local/bin/corepack \
    && corepack enable pnpm
ARG LLVM_VERSION=23
ENV PATH="/usr/local/go/bin:${PATH}" \
    CLANG=clang-${LLVM_VERSION} STRIP=llvm-strip-${LLVM_VERSION} LLVM_OBJDUMP=llvm-objdump-${LLVM_VERSION} \
    CC=/build/scripts/zig-cc.sh CGO_ENABLED=1
WORKDIR /build/
COPY scripts/setup-llvm.sh scripts/setup-zig.sh scripts/
RUN scripts/setup-llvm.sh "$LLVM_VERSION" \
    && apt-get install -y git make xz-utils binutils libatomic1 \
    && rm -rf /var/lib/apt/lists/*
RUN zig=$(scripts/setup-zig.sh /opt/dae-zig) \
    && ln -s "$zig" /usr/local/bin/zig
COPY go.mod go.sum ./
# Initialize submodules in the build context before running docker build.
COPY third_party ./third_party
RUN go mod download
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY web/package.json ./web/package.json
RUN pnpm install --frozen-lockfile
COPY . .
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=unstable-0.nogit
RUN export GOARCH="$TARGETARCH" GOARM="${TARGETVARIANT#v}" \
    && GOWORK=off make OUTPUT=dae VERSION="$VERSION" GOFLAGS="-buildvcs=false" STATIC=y PLUGINS_CONFIG=plugins.cfg.example \
    && scripts/check-static.sh dae

FROM alpine
COPY --from=builder /build/dae /usr/local/bin/dae

ENTRYPOINT ["dae"]
CMD ["run", "-c", "/etc/dae/config.dae"]
