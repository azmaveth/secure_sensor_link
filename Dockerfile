# syntax=docker/dockerfile:1

# Build, check and run the receiver without a Rust toolchain on the host.
#
#   docker build --target test --progress=plain .      formatting, lints, all tests
#   docker build -t secure-sensor-link .                the runtime image
#   docker run --rm -i secure-sensor-link < examples/spec_session.jsonl
#
# Downloaded crates and compiled dependencies are kept in BuildKit cache
# mounts, so a rebuild after a source change only recompiles this crate.

# The toolchain the project is developed and tested with. The crate's minimum
# is 1.88 (`rust-version` in Cargo.toml); to check it, pass
# --build-arg RUST_VERSION=1.88.
ARG RUST_VERSION=1.99
ARG DEBIAN_RELEASE=trixie

FROM rust:${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS toolchain
RUN rustup component add clippy rustfmt
WORKDIR /src
COPY . .

# Each Cargo step below starts by marking this crate's sources as new.
# Cargo decides whether the crate is up to date by comparing file times, and
# the cached target directory outlives any one build. Docker can restore an
# older copy of the sources (after an edit is undone, or on switching
# branches) whose times predate the last compile, and Cargo would then reuse
# output built from different code. The touch has to run in the same step as
# Cargo, or Docker would cache its result too. This crate always rebuilds;
# dependencies stay cached.

# Formatting, lints and the full test suite. The build fails if any of them do.
# Docker caches this step like any other; to run it again with nothing
# changed, pass a new value: --build-arg RERUN=$(date +%s). (--no-cache would
# also work, but it empties the cache mounts and rebuilds every dependency.)
FROM toolchain AS test
ARG RERUN
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    find src tests examples -type f -exec touch {} + \
    && cargo fmt --check \
    && cargo clippy --all-targets --locked -- -D warnings \
    && cargo test --locked

# The release binary. It is copied out of the cache mount before the step ends.
FROM toolchain AS build
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    find src tests examples -type f -exec touch {} + \
    && cargo build --release --locked --bin receiver \
    && cp target/release/receiver /usr/local/bin/receiver

# Only the binary, on the same Debian release as the toolchain image (so the
# glibc matches), running as an unprivileged user. Commands arrive on stdin,
# so run it with `docker run -i`. Diagnostics go to stderr.
FROM debian:${DEBIAN_RELEASE}-slim AS runtime
COPY --from=build /usr/local/bin/receiver /usr/local/bin/receiver
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/receiver"]
