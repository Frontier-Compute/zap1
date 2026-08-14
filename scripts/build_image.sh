#!/usr/bin/env bash
set -euo pipefail

# Build from the exact committed archive, not mutable worktree bytes.
# Usage: scripts/build_image.sh [image-tag] [receipt-path]

if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  echo "Refusing to build: the worktree is not clean." >&2
  exit 1
fi

SOURCE_REVISION="$(git rev-parse HEAD)"
SOURCE_TREE="$(git rev-parse 'HEAD^{tree}')"
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
TAG="${1:-zap1:$SOURCE_REVISION}"
BUILD_CONTEXT="$(mktemp -d)"

cleanup() {
  rm -rf -- "$BUILD_CONTEXT"
  if [ -n "${RECEIPT_TMP:-}" ]; then
    rm -f -- "$RECEIPT_TMP"
  fi
}
trap cleanup EXIT

git archive "$SOURCE_REVISION" | tar -x -C "$BUILD_CONTEXT"
SOURCE_MANIFEST_SHA256="$(
  python3 "$BUILD_CONTEXT/scripts/source_manifest.py" --root "$BUILD_CONTEXT"
)"
DOCKERFILE_SHA256="$(sha256sum "$BUILD_CONTEXT/Dockerfile" | cut -d ' ' -f1)"

docker build \
  --build-arg "SOURCE_REVISION=$SOURCE_REVISION" \
  --build-arg "SOURCE_TREE=$SOURCE_TREE" \
  --build-arg "PUBLIC_EVIDENCE_REVISION=$SOURCE_REVISION" \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --build-arg "SOURCE_MANIFEST_SHA256=$SOURCE_MANIFEST_SHA256" \
  --tag "$TAG" \
  "$BUILD_CONTEXT"

IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$TAG")"
IMAGE_HEX="${IMAGE_ID#sha256:}"
case "$IMAGE_ID" in
  sha256:*) ;;
  *) echo "Refusing receipt: invalid Docker image ID: $IMAGE_ID" >&2; exit 1 ;;
esac
case "$IMAGE_HEX" in
  ''|*[!0-9a-f]*) echo "Refusing receipt: invalid Docker image ID: $IMAGE_ID" >&2; exit 1 ;;
esac
if [ "${#IMAGE_HEX}" -ne 64 ]; then
  echo "Refusing receipt: invalid Docker image ID length: $IMAGE_ID" >&2
  exit 1
fi

IMAGE_REVISION="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE_ID")"
IMAGE_TREE="$(docker image inspect --format '{{index .Config.Labels "io.frontiercompute.zap1.source-tree"}}' "$IMAGE_ID")"
IMAGE_MANIFEST="$(docker image inspect --format '{{index .Config.Labels "io.frontiercompute.zap1.source-manifest-sha256"}}' "$IMAGE_ID")"

if [ "$IMAGE_REVISION" != "$SOURCE_REVISION" ] || \
   [ "$IMAGE_TREE" != "$SOURCE_TREE" ] || \
   [ "$IMAGE_MANIFEST" != "$SOURCE_MANIFEST_SHA256" ]; then
  echo "Refusing receipt: image labels do not match the clean archive." >&2
  exit 1
fi

BUILD_INFO="$(docker run --rm --entrypoint /bin/cat "$IMAGE_ID" /usr/local/share/zap1/BUILD_INFO)"
build_info_value() {
  printf '%s\n' "$BUILD_INFO" | awk -F= -v key="$1" '
    $1 == key { count += 1; value = substr($0, index($0, "=") + 1) }
    END { if (count == 1) print value; else exit 1 }
  '
}

EMBEDDED_REVISION="$(build_info_value source_revision)"
EMBEDDED_TREE="$(build_info_value source_tree)"
EMBEDDED_MANIFEST="$(build_info_value source_manifest_sha256)"
if [ "$EMBEDDED_REVISION" != "$SOURCE_REVISION" ] || \
   [ "$EMBEDDED_TREE" != "$SOURCE_TREE" ] || \
   [ "$EMBEDDED_MANIFEST" != "$SOURCE_MANIFEST_SHA256" ]; then
  echo "Refusing receipt: embedded BUILD_INFO does not match the clean archive." >&2
  exit 1
fi

IMAGE_SUFFIX="$(printf '%s' "${IMAGE_ID#sha256:}" | cut -c1-16)"
REPO_PARENT="$(dirname "$(git rev-parse --show-toplevel)")"
RECEIPT_PATH="${2:-${ZAP1_BUILD_RECEIPT:-$REPO_PARENT/zap1-build-receipt-$SOURCE_REVISION-$IMAGE_SUFFIX.env}}"
RECEIPT_DIR="$(dirname "$RECEIPT_PATH")"
RECEIPT_BASE="$(basename "$RECEIPT_PATH")"
case "$RECEIPT_BASE" in
  ''|*[!A-Za-z0-9._-]*)
    echo "Refusing receipt basename outside [A-Za-z0-9._-]: $RECEIPT_BASE" >&2
    exit 1
    ;;
esac
mkdir -p "$RECEIPT_DIR"
RECEIPT_DIR="$(cd "$RECEIPT_DIR" && pwd -P)"
RECEIPT_PATH="$RECEIPT_DIR/$RECEIPT_BASE"
REPO_ROOT="$(cd "$(git rev-parse --show-toplevel)" && pwd -P)"
case "$RECEIPT_PATH" in
  "$REPO_ROOT"/*)
    echo "Refusing receipt path inside the checkout: $RECEIPT_PATH" >&2
    exit 1
    ;;
esac
if [ -e "$RECEIPT_PATH" ] || [ -e "$RECEIPT_PATH.sha256" ]; then
  echo "Refusing to overwrite an existing build receipt: $RECEIPT_PATH" >&2
  exit 1
fi
RECEIPT_TMP="$RECEIPT_PATH.tmp.$$"
if [ -e "$RECEIPT_TMP" ]; then
  echo "Refusing receipt: temporary path already exists: $RECEIPT_TMP" >&2
  exit 1
fi

{
  printf 'receipt_format=zap1-build-receipt-v1\n'
  printf 'created_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'built_image=%s\n' "$TAG"
  printf 'image_id=%s\n' "$IMAGE_ID"
  printf 'source_revision=%s\n' "$SOURCE_REVISION"
  printf 'source_tree=%s\n' "$SOURCE_TREE"
  printf 'source_manifest_sha256=%s\n' "$SOURCE_MANIFEST_SHA256"
  printf 'dockerfile_sha256=%s\n' "$DOCKERFILE_SHA256"
  printf 'image_label_revision=%s\n' "$IMAGE_REVISION"
  printf 'image_label_source_tree=%s\n' "$IMAGE_TREE"
  printf 'image_label_source_manifest_sha256=%s\n' "$IMAGE_MANIFEST"
  while IFS= read -r line; do
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      ''|*[!a-z0-9_]*)
        echo "Refusing receipt: invalid BUILD_INFO key: $key" >&2
        exit 1
        ;;
    esac
    printf 'build_info_%s=%s\n' "$key" "$value"
  done <<EOF
$BUILD_INFO
EOF
} > "$RECEIPT_TMP"
mv "$RECEIPT_TMP" "$RECEIPT_PATH"
RECEIPT_TMP=

(
  cd "$RECEIPT_DIR"
  sha256sum "$RECEIPT_BASE" > "$RECEIPT_BASE.sha256"
)
RECEIPT_SHA256="$(sha256sum "$RECEIPT_PATH" | cut -d ' ' -f1)"

printf 'built_image=%s\nimage_id=%s\nsource_revision=%s\nsource_tree=%s\nsource_manifest_sha256=%s\ndockerfile_sha256=%s\nreceipt_path=%s\nreceipt_sha256=%s\n' \
  "$TAG" "$IMAGE_ID" "$SOURCE_REVISION" "$SOURCE_TREE" "$SOURCE_MANIFEST_SHA256" \
  "$DOCKERFILE_SHA256" "$RECEIPT_PATH" "$RECEIPT_SHA256"
printf '%s\n' 'bit_for_bit_reproduction=not_asserted'
