FROM rust:1.85.1-bookworm AS builder

RUN apt-get update && apt-get install -y \
    libclang-dev \
    protobuf-compiler \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock* build.rs ./
COPY src/ src/
COPY proto/ proto/
COPY zap1-verify/ zap1-verify/
COPY migrations/ migrations/
COPY tests/ tests/

# Deterministic build: eliminate timestamp-based non-determinism
# Follows the StageX/Zaino approach for reproducible builds
# SOURCE_DATE_EPOCH pins all embedded timestamps to the last git commit
# Combined with Cargo.lock + librustzcash rev-pinning for full source reproducibility
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
ENV RUSTFLAGS="--remap-path-prefix /app=zap1"

RUN cargo build --release

# Capture build metadata for verification
RUN echo "source_date_epoch=${SOURCE_DATE_EPOCH}" > /app/target/release/BUILD_INFO && \
    sha256sum /app/target/release/zap1 >> /app/target/release/BUILD_INFO && \
    sha256sum /app/target/release/anchor_root >> /app/target/release/BUILD_INFO && \
    rustc --version >> /app/target/release/BUILD_INFO

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/zap1 /usr/local/bin/
COPY --from=builder /app/target/release/anchor_root /usr/local/bin/
COPY --from=builder /app/target/release/BUILD_INFO /usr/local/share/zap1/
RUN mkdir -p /data
VOLUME /data
EXPOSE 3080
CMD ["zap1"]
