# ---------- builder ----------
FROM rust:1.82-bookworm AS builder

WORKDIR /build

# Cache dependencies by copying manifests first
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs \
    && cargo build --release 2>/dev/null || true \
    && rm -rf src

# Copy source and build for real
COPY . .
RUN cargo build --release

# ---------- runtime ----------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/catbird-server /usr/local/bin/catbird-server
COPY --from=builder /build/migrations /app/migrations

RUN groupadd --system catbird && useradd --system --gid catbird --home-dir /app --shell /usr/sbin/nologin catbird \
    && chown -R catbird:catbird /app

WORKDIR /app
EXPOSE 3001

ENV SERVER_PORT=3001
USER catbird
CMD ["catbird-server"]
