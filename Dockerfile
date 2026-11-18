FROM --platform=$BUILDPLATFORM golang:1.27.2 AS go-toolchain
FROM --platform=$BUILDPLATFORM node:26-bookworm-slim AS node-toolchain
RUN npm install --global corepack@0.36.0

FROM --platform=$BUILDPLATFORM ubuntu:24.04 AS builder
COPY --from=go-toolchain /usr/local/go /usr/local/go
COPY --from=node-toolchain /usr/local/bin/node /usr/local/bin/node
COPY --from=node-toolchain /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/corepack/dist/pnpm.js /usr/local/bin/pnpm
ARG LLVM_VERSION=23
ENV PATH="/usr/local/go/bin:${PATH}" \
    CLANG=clang-${LLVM_VERSION} STRIP=llvm-strip-${LLVM_VERSION} LLVM_OBJDUMP=llvm-objdump-${LLVM_VERSION} \
    CC=/usr/local/bin/dae-musl-cc CGO_ENABLED=1
WORKDIR /build/
COPY scripts/setup-llvm.sh scripts/
RUN scripts/setup-llvm.sh "$LLVM_VERSION" \
    && apt-get install -y git make xz-utils binutils libatomic1 \
    && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
# Initialize submodules in the build context before running docker build.
COPY third_party ./third_party
RUN go mod download
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY web/package.json ./web/package.json
RUN pnpm install --frozen-lockfile
ARG TARGETARCH
ARG TARGETVARIANT
COPY scripts/setup-musl.sh scripts/setup-mips64-softfloat.sh scripts/musl-cross.sha256 scripts/
RUN cc=$(GOARCH="$TARGETARCH" GOARM="${TARGETVARIANT#v}" scripts/setup-musl.sh /opt/dae-musl) \
    && ln -s "$cc" "$CC"
COPY . .
ARG VERSION=unstable-0.nogit
RUN export GOARCH="$TARGETARCH" GOARM="${TARGETVARIANT#v}" \
    && GOWORK=off make OUTPUT=dae VERSION="$VERSION" GOFLAGS="-buildvcs=false" STATIC=y PLUGINS_CONFIG=plugins.cfg.example \
    && scripts/check-static.sh dae

FROM alpine
COPY --from=builder /build/dae /usr/local/bin/dae

ENTRYPOINT ["dae"]
CMD ["run", "-c", "/etc/dae/config.dae"]
