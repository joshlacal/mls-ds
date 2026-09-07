# syntax=docker/dockerfile:1.7

# ---------- builder ----------
FROM rust:1-bookworm AS builder

WORKDIR /build

COPY --from=catbird-atproto / /catbird-atproto

# Cache dependencies by copying manifests first
COPY Cargo.toml Cargo.lock* ./
COPY server/Cargo.toml server/Cargo.toml
COPY codegen/Cargo.toml codegen/Cargo.toml
COPY vendor vendor
RUN mkdir -p server/src codegen/src \
    && echo "fn main() {}" > server/src/main.rs \
    && echo "" > server/src/lib.rs \
    && echo "fn main() {}" > codegen/src/main.rs \
    && (cargo build --release -p catbird-server 2>/dev/null || true) \
    && cargo clean --release -p catbird-server \
    && rm -rf server/src codegen/src

# Copy source and build for real
COPY server server
COPY codegen codegen
COPY lexicon lexicon
COPY e2e-tests e2e-tests
RUN cargo build --release -p catbird-server

# ---------- runtime-base ----------
FROM debian:bookworm-slim AS runtime-base

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system catbird && useradd --system --gid catbird --home-dir /app --shell /usr/sbin/nologin catbird \
    && chown -R catbird:catbird /app

WORKDIR /app
EXPOSE 3001

ENV SERVER_PORT=3001
USER catbird

# ---------- federation-test-builder ----------
FROM builder AS federation-test-builder

RUN cargo build --release -p catbird-server --bin catbird-server --bin federation_fixture --features test-support

# ---------- federation-test ----------
FROM runtime-base AS federation-test

USER root
COPY --from=federation-test-builder /build/target/release/catbird-server /usr/local/bin/catbird-server
COPY --from=federation-test-builder /build/target/release/federation_fixture /usr/local/bin/federation_fixture
COPY --from=builder /build/server/migrations /app/migrations
COPY --from=builder /build/e2e-tests/fixtures /app/fixtures
RUN chown -R catbird:catbird /app && chmod +x /usr/local/bin/federation_fixture

USER catbird
CMD ["catbird-server"]

# ---------- runtime (final default stage) ----------
FROM runtime-base AS runtime

USER root
COPY --from=builder /build/target/release/catbird-server /usr/local/bin/catbird-server
COPY --from=builder /build/server/migrations /app/migrations
RUN chown -R catbird:catbird /app

USER catbird
CMD ["catbird-server"]
