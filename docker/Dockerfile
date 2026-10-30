# Official Orblx node image (W25-8).
# Stage 1 builds a static musl release binary.
# Stage 2 adds the tools that the node calls to Alpine. Stage 3 copies that root file system into one flat layer.
# The image has no token, no key, and no certificate. The node gets these at run time.
# Build from the repository root:
#   docker build -f docker/Dockerfile -t orblx:local .

ARG RUST_IMAGE=rust:1-alpine
ARG RUNTIME_IMAGE=alpine:3.22

FROM ${RUST_IMAGE} AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p orblx-cli --bin orblx \
    && strip target/release/orblx \
    && cp target/release/orblx /orblx

FROM ${RUNTIME_IMAGE} AS rootfs
# ip is required. iptables is for subnet routes and exit nodes.
RUN apk add --no-cache iproute2 iptables
COPY --from=build /orblx /usr/local/bin/orblx
COPY docker/entrypoint.sh /usr/local/bin/orblx-entrypoint
# The node uses only the coordinator trust bundle from its state directory.
# Remove the public CA bundle and the apk signing keys, so that the image has no PEM item.
# Remove the apk database too, because apk cannot verify packages without the keys.
RUN chmod 755 /usr/local/bin/orblx /usr/local/bin/orblx-entrypoint \
    && rm -rf /etc/ssl /usr/share/ca-certificates /etc/apk/keys /usr/share/apk \
        /lib/apk /etc/apk /var/cache/apk /sbin/apk \
    && mkdir -p /var/lib/orblx \
    && chmod 700 /var/lib/orblx

# One flat layer: the removed files are not in a lower layer.
FROM scratch
COPY --from=rootfs / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
VOLUME ["/var/lib/orblx"]
LABEL org.opencontainers.image.title="orblx" \
      org.opencontainers.image.source="https://github.com/KimSeogyu/Orblx" \
      org.opencontainers.image.licenses="Apache-2.0"
ENTRYPOINT ["/usr/local/bin/orblx-entrypoint"]
CMD ["node"]
