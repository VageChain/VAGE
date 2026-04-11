# --- Multi-Stage Build Strategy for VageChain ---
# Stage 1: Build the optimized Rust binaries
FROM rust:1.75-slim-bookworm as builder

# Install build dependencies (openssl, libssl-dev, etc. for network crates)
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/vagechain
COPY . .

# Build only the node binary in release mode
RUN cargo build --release --bin vagechain

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the optimized binary from the builder stage
COPY --from=builder /usr/src/vagechain/target/release/vagechain /usr/local/bin/vagechain

# Expose standard P2P and RPC ports
EXPOSE 9000 8080 30333

# Use the 'vagechain' binary as the default entry point
ENTRYPOINT ["vagechain"]
CMD ["--config", "configs/node.json"]
