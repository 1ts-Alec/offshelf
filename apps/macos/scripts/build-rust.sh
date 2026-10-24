#!/bin/sh
# Builds the Rust engine as a static library and regenerates its Swift
# bindings. Xcode runs this before compiling; it also works by hand.
set -eu
here="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "$here/../.." && pwd)"
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

profile="release"
if [ "${CONFIGURATION:-Release}" = "Debug" ]; then profile="debug"; fi
flag=""; [ "$profile" = "release" ] && flag="--release"

out="$here/build/rust"
mkdir -p "$out"
libs=""
# Bindings are read from one thin library; the fat one confuses uniffi.
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  if rustup target list --installed 2>/dev/null | grep -qx "$target"; then
    cargo build $flag --manifest-path "$root/Cargo.toml" -p oshelf-mac --lib --target "$target"
    libs="$libs $root/target/$target/$profile/liboshelf_mac.a"
    first="${first:-$root/target/$target/$profile/liboshelf_mac.a}"
  fi
done
if [ -z "$libs" ]; then
  cargo build $flag --manifest-path "$root/Cargo.toml" -p oshelf-mac --lib
  libs="$root/target/$profile/liboshelf_mac.a"
  first="$libs"
fi
# One library for every architecture we built.
lipo -create $libs -output "$out/liboshelf_mac.a"

gen="$here/build/gen"
cargo run -q --manifest-path "$root/Cargo.toml" -p oshelf-mac --bin uniffi-bindgen -- \
  generate --library "$first" --language swift --out-dir "$gen"
mkdir -p "$out/include"
cp "$gen/oshelf_macFFI.h" "$out/include/"
cp "$gen/oshelf_macFFI.modulemap" "$out/include/module.modulemap"
# The Swift side of the bindings is checked in; refresh it only on change
# so Xcode doesn't recompile it every build.
cmp -s "$gen/oshelf_mac.swift" "$here/Offshelf/Generated/oshelf_mac.swift" \
  || cp "$gen/oshelf_mac.swift" "$here/Offshelf/Generated/oshelf_mac.swift"
