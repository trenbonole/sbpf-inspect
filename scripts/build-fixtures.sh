#!/usr/bin/env bash
# Rebuild the test programs in fixtures/ into tests/fixtures/.
# Needs the Solana toolchain (cargo-build-sbf). Recorded build: cargo-build-sbf 4.1.0, platform-tools v1.54.
set -euo pipefail
cd "$(dirname "$0")/.."
for f in anchor-demo native-demo; do
  cargo build-sbf --manifest-path "fixtures/$f/Cargo.toml" --sbf-out-dir tests/fixtures
done
rm -f tests/fixtures/*-keypair.json
