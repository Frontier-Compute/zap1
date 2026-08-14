ARG SOURCE_REVISION
ARG SOURCE_TREE
ARG PUBLIC_EVIDENCE_REVISION
ARG SOURCE_DATE_EPOCH
ARG SOURCE_MANIFEST_SHA256

FROM rust:1.85.1-bookworm AS builder

ARG SOURCE_REVISION
ARG SOURCE_TREE
ARG PUBLIC_EVIDENCE_REVISION
ARG SOURCE_DATE_EPOCH
ARG SOURCE_MANIFEST_SHA256

RUN printf '%s' "${SOURCE_REVISION}" | grep -Eq '^[0-9a-f]{40}$' \
    && printf '%s' "${SOURCE_TREE}" | grep -Eq '^[0-9a-f]{40}$' \
    && printf '%s' "${PUBLIC_EVIDENCE_REVISION}" | grep -Eq '^[0-9a-f]{40}$' \
    && printf '%s' "${SOURCE_DATE_EPOCH}" | grep -Eq '^[0-9]+$' \
    && printf '%s' "${SOURCE_MANIFEST_SHA256}" | grep -Eq '^[0-9a-f]{64}$'

RUN apt-get update && apt-get install -y \
    libclang-dev \
    protobuf-compiler \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock build.rs ./
COPY src/ src/
COPY proto/ proto/
COPY zap1-verify/ zap1-verify/
COPY zcash-memo-decode/ zcash-memo-decode/
COPY migrations/ migrations/
COPY tests/ tests/

# Bind the image to the exact runtime-source bytes copied into this stage.
RUN export LC_ALL=C; \
    actual="$(find Cargo.toml Cargo.lock build.rs src proto zap1-verify zcash-memo-decode migrations tests -type f -print0 \
      | sort -z \
      | xargs -0 sha256sum \
      | sha256sum \
      | cut -d ' ' -f1)"; \
    test "${actual}" = "${SOURCE_MANIFEST_SHA256}"

# These settings reduce known path/time variance. The metadata identifies the
# declared build inputs; it is not a claim of bit-for-bit reproducibility.
ENV SOURCE_REVISION=${SOURCE_REVISION}
ENV SOURCE_TREE=${SOURCE_TREE}
ENV PUBLIC_EVIDENCE_REVISION=${PUBLIC_EVIDENCE_REVISION}
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
ENV RUSTFLAGS="--remap-path-prefix /app=zap1"

RUN cargo build --release --locked

# Capture machine-readable declared inputs and resulting artifact hashes.
RUN { \
      echo "source_revision=${SOURCE_REVISION}"; \
      echo "source_tree=${SOURCE_TREE}"; \
      echo "public_evidence_revision=${PUBLIC_EVIDENCE_REVISION}"; \
      echo "source_date_epoch=${SOURCE_DATE_EPOCH}"; \
      echo "source_manifest_sha256=${SOURCE_MANIFEST_SHA256}"; \
      echo "source_manifest_verified=true"; \
      echo "cargo_locked=true"; \
      echo "path_remapping=true"; \
      echo "cargo_lock_sha256=$(sha256sum Cargo.lock | cut -d ' ' -f1)"; \
      echo "zap1_binary_sha256=$(sha256sum /app/target/release/zap1 | cut -d ' ' -f1)"; \
      echo "anchor_root_binary_sha256=$(sha256sum /app/target/release/anchor_root | cut -d ' ' -f1)"; \
      echo "rustc_version=$(rustc --version)"; \
    } > /app/target/release/BUILD_INFO

FROM debian:bookworm-slim

ARG SOURCE_REVISION
ARG SOURCE_TREE
ARG PUBLIC_EVIDENCE_REVISION
ARG SOURCE_DATE_EPOCH
ARG SOURCE_MANIFEST_SHA256

LABEL org.opencontainers.image.source="https://github.com/Frontier-Compute/zap1" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      io.frontiercompute.zap1.source-tree="${SOURCE_TREE}" \
      io.frontiercompute.zap1.public-evidence-revision="${PUBLIC_EVIDENCE_REVISION}" \
      io.frontiercompute.zap1.source-date-epoch="${SOURCE_DATE_EPOCH}" \
      io.frontiercompute.zap1.source-manifest-sha256="${SOURCE_MANIFEST_SHA256}"

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/zap1 /usr/local/bin/
COPY --from=builder /app/target/release/anchor_root /usr/local/bin/
COPY --from=builder /app/target/release/BUILD_INFO /usr/local/share/zap1/
RUN mkdir -p /data
VOLUME /data
EXPOSE 3080
CMD ["zap1"]
