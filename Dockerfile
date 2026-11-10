# Dockerfile for OpenAPPA Enhanced
# Multi-stage build for minimal production image

# ============================================================
# STAGE 1: Build
# ============================================================
FROM rust:1.99-bookworm AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY appa-engine/ ./appa-engine/
COPY appa-policy/ ./appa-policy/
COPY appa-runtime/ ./appa-runtime/
COPY appa-eventlog/ ./appa-eventlog/
COPY appa-builtin/ ./appa-builtin/
COPY appa-runtime-api/ ./appa-runtime-api/
COPY appa-package/ ./appa-package/
COPY appa-adapter-amp/ ./appa-adapter-amp/
COPY appa-adapter-opencode/ ./appa-adapter-opencode/
COPY appa-adapter-claude-code/ ./appa-adapter-claude-code/
COPY appa-adapter-kagent/ ./appa-adapter-kagent/
COPY appa-file-tracker/ ./appa-file-tracker/

# Build the runtime binary
RUN cargo build --release --package appa --features daemon

# ============================================================
# STAGE 2: Runtime
# ============================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appa && useradd -r -g appa -d /data -s /sbin/nologin appa

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/appa /usr/local/bin/appa

# Create data directory
RUN mkdir -p /data && chown -R appa:appa /data

# Switch to non-root user
USER appa

# Expose ports
EXPOSE 8787

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:8787/health || exit 1

# Default command
ENTRYPOINT ["appa"]
CMD ["runtime", "--config", "/data/appa.toml", "--db", "/data/appa.db"]