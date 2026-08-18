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
RUN cargo build --release -p catbird-server

# ---------- runtime ----------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/catbird-server /usr/local/bin/catbird-server
COPY --from=builder /build/server/migrations /app/migrations

RUN groupadd --system catbird && useradd --system --gid catbird --home-dir /app --shell /usr/sbin/nologin catbird \
    && chown -R catbird:catbird /app

WORKDIR /app
EXPOSE 3001

ENV SERVER_PORT=3001
USER catbird
CMD ["catbird-server"]
