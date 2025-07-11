# Multi-stage build for optimal image size
FROM rust:1.85-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libdbus-1-dev \
    gcc-11 \
    g++-11 \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 100 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-11 100

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r signer && useradd -r -g signer signer

# Create app directory and set permissions
WORKDIR /app
RUN chown signer:signer /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/starknet-remote-signer /usr/local/bin/starknet-remote-signer
RUN chmod +x /usr/local/bin/starknet-remote-signer

# Switch to non-root user
USER signer

# Default port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Default command
CMD ["starknet-remote-signer"] 