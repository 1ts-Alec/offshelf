#!/bin/sh
# Builds crates/oshelf-web for the browser into src/wasm (not checked in).
# Needs: rustup target add wasm32-unknown-unknown, and
# cargo install wasm-bindgen-cli --version 0.2.100
set -eu
cd "$(dirname "$0")/../../.."
# On macOS, Apple's ar writes archives the wasm linker can't read, so zstd's
# C code would silently drop out. Use LLVM's (rustup component llvm-tools).
if [ "$(uname)" = Darwin ] && [ -z "${AR_wasm32_unknown_unknown:-}" ]; then
  ar=$(find "$(rustc --print sysroot)/lib/rustlib" -name llvm-ar 2>/dev/null | head -1)
  [ -n "$ar" ] && export AR_wasm32_unknown_unknown="$ar"
fi
cargo build -p oshelf-web --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir apps/web/src/wasm \
  target/wasm32-unknown-unknown/release/oshelf_web.wasm
