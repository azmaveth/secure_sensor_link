#!/bin/sh
# Builds the fuzz targets with coverage instrumentation and runs them.
#
#   ./fuzz/run.sh                 every target, 60 seconds each
#   ./fuzz/run.sh tree 600        one target, for ten minutes
#   ./fuzz/run.sh all 900         every target, fifteen minutes each
#
# Needs only the stable Rust toolchain and a C++ compiler (libFuzzer is
# built from source by the libfuzzer-sys crate). The instrumentation flags
# are the ones cargo-fuzz passes; no sanitizer is used, because sanitizers
# need a nightly toolchain and the receiver has no unsafe code for one to
# watch. Overflow checks and debug assertions are on (see Cargo.toml).
#
# Each run starts from fuzz/seeds/<target>/ (committed: the spec's example
# frames, payloads and commands) and from fuzz/corpus/<target>/, where
# libFuzzer keeps every input that reached new code, so a later run carries
# on from where an earlier one got to. A crash is saved under
# fuzz/artifacts/<target>/ and the script stops with a non-zero status.
set -eu

cd "$(dirname "$0")"
targets="${1:-all}"
seconds="${2:-60}"
if [ "$targets" = all ]; then targets="frame tree lines session"; fi

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
    "corpus/$target" $( [ -d "seeds/$target" ] && echo "seeds/$target" )
done
