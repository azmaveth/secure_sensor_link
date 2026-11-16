#!/bin/sh
# Builds the fuzz targets with coverage instrumentation and runs them.
#
#   ./fuzz/run.sh                 every target, 60 seconds each
#   ./fuzz/run.sh tree 600        one target, for ten minutes
#
# Needs only the stable Rust toolchain and a C++ compiler (libFuzzer is
# built from source by the libfuzzer-sys crate). The instrumentation flags
# are the ones cargo-fuzz passes; no sanitizer is used, because sanitizers
# need a nightly toolchain and the receiver has no unsafe code for one to
# watch. Overflow checks and debug assertions are on (see Cargo.toml).
#
# A crash is saved under fuzz/artifacts/<target>/ and the script stops with
# a non-zero status. Inputs worth keeping go to fuzz/corpus/<target>/.
set -eu

cd "$(dirname "$0")"
seconds="${2:-60}"
if [ "$#" -ge 1 ]; then targets="$1"; else targets="frame tree lines session"; fi

host="$(rustc -vV | sed -n 's/^host: //p')"
RUSTFLAGS="--cfg fuzzing \
  -Cpasses=sancov-module \
  -Cllvm-args=-sanitizer-coverage-level=4 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares \
  -Ccodegen-units=1"
export RUSTFLAGS
cargo build --release --locked --target "$host"

for target in $targets; do
  mkdir -p "corpus/$target" "artifacts/$target"
  echo "== $target: ${seconds}s"
  "target/$host/release/$target" \
    -max_total_time="$seconds" \
    -max_len=4096 \
    -timeout=10 \
    -rss_limit_mb=1024 \
    -print_final_stats=1 \
    -artifact_prefix="artifacts/$target/" \
    "corpus/$target"
done
