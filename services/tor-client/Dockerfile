# Build stage
FROM rust:1.92-slim-bookworm AS builder

# Install build dependencies (protoc needed by tonic-build for proto crate compilation)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY services ./services

# Build tor-client in release mode
RUN cargo build --release --package tor-client

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 torclient && \
    mkdir -p /app && \
    chown -R torclient:torclient /app

WORKDIR /app

COPY --from=builder /app/target/release/tor-client /app/tor-client
RUN chown torclient:torclient /app/tor-client

USER torclient

EXPOSE 1080

ENV RUST_LOG=info

ENTRYPOINT ["/app/tor-client"]
CMD ["--socks-addr", "0.0.0.0:1080", "--directory-url", "http://discovery:8080", "--pool-size", "3"]
