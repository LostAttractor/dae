FROM golang:1.27.0-bookworm AS builder
RUN apt-get update && apt-get install -y llvm-15 clang-15 git make
ENV CLANG=clang-15
WORKDIR /build/
ADD go.mod go.sum ./
RUN go mod download
ADD . .
RUN make OUTPUT=dae GOFLAGS="-buildvcs=false" CC=clang CGO_ENABLED=0

FROM alpine
RUN mkdir -p /usr/local/share/dae/
RUN mkdir -p /etc/dae/
COPY install/geodata.env /tmp/geodata.env
RUN . /tmp/geodata.env \
    && wget -O /usr/local/share/dae/geoip.dat "https://github.com/v2fly/geoip/releases/download/${GEOIP_VERSION}/geoip.dat" \
    && echo "${GEOIP_SHA256}  /usr/local/share/dae/geoip.dat" | sha256sum -c - \
    && wget -O /usr/local/share/dae/geosite.dat "https://github.com/v2fly/domain-list-community/releases/download/${GEOSITE_VERSION}/dlc.dat" \
    && echo "${GEOSITE_SHA256}  /usr/local/share/dae/geosite.dat" | sha256sum -c - \
    && rm /tmp/geodata.env
COPY --from=builder /build/dae /usr/local/bin
COPY --from=builder /build/install/empty.dae /etc/dae/config.dae
RUN chmod 0600 /etc/dae/config.dae

CMD ["dae"]
ENTRYPOINT ["dae", "run", "-c", "/etc/dae/config.dae"]
