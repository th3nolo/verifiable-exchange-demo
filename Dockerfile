# Build the release binary, then ship only the binary.
#
# rusqlite is built with the "bundled" feature, so SQLite is compiled in and
# the runtime image needs no database package. The services talk to each other
# over loopback inside this container; ca-certificates is here only so an
# outbound HTTPS call (an anchor, a webhook) does not fail obscurely later.

FROM rust:1.91-slim-bookworm@sha256:8514999d4786ef12efe89239e86b3d0a021b94b9d35108c8efe6c79ca7dc1a65 AS build

# reqwest links OpenSSL through openssl-sys, which needs pkg-config and the
# development headers at build time. Switching reqwest to rustls would remove
# this and the runtime libssl3 below, but that is a change to the application's
# TLS stack and does not belong in a Dockerfile.
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Dependencies first, so a source-only change does not refetch and rebuild the
# whole tree. The dummy main is replaced by the real sources below.
COPY services/Cargo.toml services/Cargo.lock services/rust-toolchain.toml ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs \
    && cargo build --release --locked 2>/dev/null || true

COPY services/src ./src
COPY services/static ./static

# Which commit this binary is built from. The exchange reads it at compile
# time with `option_env!` and serves it on `/market`, so an operator can read
# back which source a running deployment came from. The workflow passes the
# same commit it tags the image with.
#
# Declared here and not above, because the value changes on every commit and
# would otherwise drop the cached dependency build.
ARG BUILD_COMMIT
# Cargo skips a rebuild when mtimes look unchanged; touch to force it.
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# The anchor sender is a separate program in a separate language, so it gets a
# separate stage: it writes to a public blockchain with a key the exchange
# itself never sees, and nothing it depends on belongs in the exchange's build.
# CGO_ENABLED=0 because the runtime image is not the Go image.
FROM golang:1.26-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS anchor-build
WORKDIR /src
COPY anchor/go.mod anchor/go.sum ./
RUN go mod download
COPY anchor/*.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /anchor-sender .

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Runs unprivileged. The data directory is the only writable path it needs.
RUN useradd --system --create-home --uid 10001 exchange \
    && mkdir -p /data && chown exchange:exchange /data

COPY --from=build /src/target/release/services /usr/local/bin/services
COPY --from=anchor-build /anchor-sender /usr/local/bin/anchor-sender
# Which contract this image anchors to. Public information: an address, a
# chain id and an RPC. The matcher serves it to the browser so a visitor
# can read the anchor log from the chain themselves. The private key is not
# here and never is: it arrives at runtime as a mounted file.
#
# The ROOT record, not `deployment.json`. That one names `ExchangeAnchor`
# 0x2A4A287E, which is closed: it holds 152 chain-hash anchors, read from the
# chain on 17 August 2026, and it takes no more. The sender in this image
# writes roots, so it needs `ExchangeRootAnchor` and refuses the other one by
# the width `latest()` returns.
#
# Baking the closed record meant the image only worked when a runtime
# ANCHOR_CONTRACT override short-circuited the file read.
# Remove that one variable and the sender exited 1 in a restart loop, and
# ANCHOR_CONFIG still told every browser to read the frozen contract while the
# sender wrote to a different one.
COPY anchor/root-deployment.json /etc/exchange/anchor-deployment.json
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
# The messages that open an empty log. A separate file because ./demo.sh and
# services/tests/genesis.rs run the same one, so a deployment, a local run and
# the test open a log the same way.
COPY docker/open-the-log.sh /usr/local/bin/open-the-log.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/open-the-log.sh

USER exchange
WORKDIR /data
VOLUME ["/data"]

# 3000 feed, 3001 matcher (the UI), 3002 inbox, 3010-3012 validators.
EXPOSE 3000 3001 3002 3010 3011 3012

# Traefik reaches the matcher; a failing UI is the signal that matters.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -sf http://127.0.0.1:3001/market > /dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
