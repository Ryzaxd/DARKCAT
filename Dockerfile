# Build stage
FROM rust:1.84-slim as builder

WORKDIR /usr/src/app

# Install build dependencies (including cmake and nasm for aws-lc-sys)
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev cmake nasm && \
    rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies (including Tor)
RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 tor curl && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /usr/src/app/target/release/DARKCAT /usr/local/bin/darkweb-forensics

# Copy entrypoint script
COPY docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["status"]