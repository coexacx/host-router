#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
arch="${1:-x86_64-unknown-linux-musl}"
cargo build --locked --release --target "$arch" -j "${BUILD_JOBS:-2}"
case "$arch" in x86_64-*) name=amd64;; aarch64-*) name=arm64;; *) name="$arch";; esac
mkdir -p bin
cp "${CARGO_TARGET_DIR:-target}/$arch/release/host-router" "bin/host-router-linux-$name"
sha256sum bin/host-router-linux-* > SHA256SUMS
