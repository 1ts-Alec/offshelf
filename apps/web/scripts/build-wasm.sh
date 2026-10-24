#!/bin/sh
# Builds crates/oshelf-web for the browser into src/wasm (not checked in).
# Needs: rustup target add wasm32-unknown-unknown, and
# cargo install wasm-bindgen-cli --version 0.2.100
set -eu
cd "$(dirname "$0")/../../.."
cargo build -p oshelf-web --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir apps/web/src/wasm \
  target/wasm32-unknown-unknown/release/oshelf_web.wasm
