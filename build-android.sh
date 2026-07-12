#!/usr/bin/env bash
# Android build script for yggmail-mobile
#
# Requires: Rust with Android targets, Android NDK, cargo-ndk (⚠ version not verified)
#
# Setup once:
#   rustup target add aarch64-linux-android x86_64-linux-android armv7-linux-androideabi i686-linux-android
#   cargo install cargo-ndk
#   export ANDROID_NDK_HOME=/path/to/android-ndk
#
# Usage:
#   ./build-android.sh --target arm64            # one target (alias)
#   ./build-android.sh --target arm64 --target x86_64
#   ./build-android.sh arm64 x86                  # positional tokens
#   ./build-android.sh aarch64-linux-android      # full triple accepted
#   ./build-android.sh --all                      # all four targets
#   ./build-android.sh -h | --help                # show usage
#
# Default (no args): print usage and exit 1 — do NOT build everything silently.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ponytail: minimal associative arrays; declare explicitly for determinism.
declare -A ALIAS=(
    ["arm64"]="aarch64-linux-android"
    ["x86_64"]="x86_64-linux-android"
    ["arm"]="armv7-linux-androideabi"
    ["x86"]="i686-linux-android"
)

declare -A ABI=(
    ["aarch64-linux-android"]="arm64-v8a"
    ["x86_64-linux-android"]="x86_64"
    ["armv7-linux-androideabi"]="armeabi-v7a"
    ["i686-linux-android"]="x86"
)

ALL_TARGETS=(
    "aarch64-linux-android"
    "x86_64-linux-android"
    "armv7-linux-androideabi"
    "i686-linux-android"
)

usage() {
    cat <<EOF
Usage: $0 [--target <alias|triple>]... [<alias|triple>...] [--all] [-h|--help]

Targets (alias -> triple):
  arm64  -> aarch64-linux-android
  x86_64 -> x86_64-linux-android
  arm    -> armv7-linux-androideabi
  x86    -> i686-linux-android

Full triples are also accepted directly.

Flags:
  --target <token>   add a target (repeatable)
  --all              build all four targets
  -h, --help         show this help and exit

Examples:
  $0 --target arm64
  $0 arm64 x86_64
  $0 --all
EOF
}

# Resolve one token (alias or triple) to a canonical triple. Echoes the triple
# on success; on failure prints an error and exits non-zero (caller wraps in if).
resolve_token() {
    local token="$1"
    if [[ -n "${ALIAS[$token]:-}" ]]; then
        echo "${ALIAS[$token]}"
        return 0
    fi
    if [[ -n "${ABI[$token]:-}" ]]; then
        echo "$token"
        return 0
    fi
    echo "ERROR: unknown target '$token'" >&2
    echo "Valid aliases: arm64, x86_64, arm, x86" >&2
    echo "Valid triples: ${ALL_TARGETS[*]}" >&2
    return 1
}

# Add a triple to SELECTED unless already present (preserve first-seen order).
declare -a SELECTED=()
declare -A SEEN=()
add_target() {
    local triple="$1"
    if [[ -z "${SEEN[$triple]:-}" ]]; then
        SELECTED+=("$triple")
        SEEN[$triple]=1
    fi
}

BUILD_ALL=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --all)
            BUILD_ALL=1
            shift
            ;;
        --target)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --target requires an argument" >&2
                exit 1
            fi
            triple="$(resolve_token "$2")" || exit 1
            add_target "$triple"
            shift 2
            ;;
        --target=*)
            token="${1#--target=}"
            triple="$(resolve_token "$token")" || exit 1
            add_target "$triple"
            shift
            ;;
        --*)
            echo "ERROR: unknown flag '$1'" >&2
            usage >&2
            exit 1
            ;;
        *)
            triple="$(resolve_token "$1")" || exit 1
            add_target "$triple"
            shift
            ;;
    esac
done

# ponytail: --all expands to the canonical set in fixed order, ignoring any
# individually-listed duplicates.
if [[ "$BUILD_ALL" -eq 1 ]]; then
    SELECTED=()
    SEEN=()
    for t in "${ALL_TARGETS[@]}"; do
        add_target "$t"
    done
fi

if [[ ${#SELECTED[@]} -eq 0 ]]; then
    usage
    exit 1
fi

echo "=== Building yggmail-mobile for Android ==="
echo "Targets: ${SELECTED[*]}"
echo ""

for target in "${SELECTED[@]}"; do
    echo "--- Building for $target ---"
    cargo ndk \
        --target "$target" \
        --platform 21 \
        -- build --release -p yggmail-mobile
done

# Bindings are arch-independent: use the .so from the FIRST selected target,
# never a hardcoded aarch64 path (would break for x86-only builds).
FIRST_TRIPLE="${SELECTED[0]}"
SO_PATH="target/${FIRST_TRIPLE}/release/libyggmail_mobile.so"

echo "--- Generating Kotlin bindings (from $SO_PATH) ---"
cargo run --bin uniffi-bindgen -- generate \
    --lib-file "$SO_PATH" \
    --language kotlin \
    --out-dir kotlin-bindings

echo ""
echo "=== Done! ==="
echo "Kotlin bindings: kotlin-bindings/uniffi/yggmail_mobile/"
echo ""
echo "Copy manually to Android project:"
for target in "${SELECTED[@]}"; do
    abi="${ABI[$target]}"
    echo "  target/${target}/release/libyggmail_mobile.so  ->  app/src/main/jniLibs/${abi}/libyggmail_mobile.so"
done
echo "  kotlin-bindings/uniffi/yggmail_mobile/yggmail_mobile.kt  ->  app/src/main/java/uniffi/yggmail_mobile/"
