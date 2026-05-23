# ========================================================
# Stage 1: High-Performance Hardened Builder
# ========================================================
FROM rust:alpine AS builder

# Install secure compilation dependencies
RUN apk add --no-cache musl-dev pkgconfig openssl-dev

WORKDIR /usr/src/solomon

# Copy source manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy source files to cache dependencies and avoid full recompilation
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN cargo build --release --features proxy
RUN rm -rf src

# Copy real source code
COPY src ./src

# Force a rebuild of the actual source code with full release optimizations, symbol stripping and proxy feature
RUN touch src/main.rs src/lib.rs && cargo build --release --features proxy

# ========================================================
# Stage 2: Ultra-Minimal Hardened Enterprise Runtime
# ========================================================
FROM alpine:latest AS runtime

# Hardening: Install minimal certs and create non-privileged runtime user
RUN apk add --no-cache ca-certificates \
    && addgroup -S solomon \
    && adduser -S solomon -G solomon

WORKDIR /home/solomon
USER solomon

# Copy ONLY the compiled statically-linked binary from builder
COPY --from=builder /usr/src/solomon/target/release/ml-dsa-65 /usr/local/bin/solomon-proxy

EXPOSE 8080

# Configure crash-only post-quantum environment variables by default
ENV PROXY_LISTEN_ADDR=127.0.0.1:8080
ENV BACKEND_URL=http://127.0.0.1:8081
ENV CONTROL_PLANE_URL=http://127.0.0.1:9000
ENV LICENSE_ID=ENT-5821

# Launch the secure proxy gateway
CMD ["/usr/local/bin/solomon-proxy"]
