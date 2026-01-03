# Build stage
FROM rust:1.84-slim as builder

WORKDIR /usr/src/app

# Build deps (cmake+nasm kan være nødvendigt for visse crypto deps; ok at beholde)
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev cmake nasm && \
    rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Cache deps
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source + build
COPY src ./src
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Runtime deps: Tor + certs + curl til readiness-check
RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 tor curl && \
    rm -rf /var/lib/apt/lists/*

# Copy binary
COPY --from=builder /usr/src/app/target/release/DARKCAT /usr/local/bin/darkcat

# Entrypoint
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["status"]
