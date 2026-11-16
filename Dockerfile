# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# Build, check and run the receiver without a Rust toolchain on the host.
#
#   docker build --target test --progress=plain .      formatting, lints, all tests
#   docker build --target audit --progress=plain .     known vulnerabilities in dependencies
#   docker build -t secure-sensor-link .                the runtime image
#   docker run --rm -i secure-sensor-link < examples/spec_session.jsonl
#   docker run --rm -i secure-sensor-link --diagnostics security < ...   with diagnostics
#
# Downloaded crates and compiled dependencies are kept in BuildKit cache
# mounts, so a rebuild after a source change only recompiles this crate.

# Every image is pinned by digest, so a tag that is moved or replaced upstream
# can't change what gets built. The digests are those of the multi-platform
# indexes, so they work on amd64 and arm64 alike. They were resolved on
# 2026-11-16; to update one, look up the tag's current digest with
#   docker buildx imagetools inspect <image>:<tag>
# and replace it here (the first line pins the Dockerfile frontend the same
# way).
#
# RUST_IMAGE is the toolchain the project is developed and tested with. The
# crate's minimum is 1.88 (`rust-version` in Cargo.toml); to check it, pass
# --build-arg RUST_IMAGE=rust:1.88-slim-trixie (ideally with its digest).
# RUNTIME_IMAGE must be the same Debian release as RUST_IMAGE, so the glibc
# the binary was linked against matches the one it runs on.
ARG RUST_IMAGE=rust:1.99-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7
ARG RUNTIME_IMAGE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# cargo-audit, as the binary its maintainers publish for each release, checked
# against a pinned SHA-256 before use (the build fails if it differs).
# Building it from source instead takes several minutes and more memory than
# a default-sized Docker VM has. One stage per architecture, because the
# checksum differs; only the one matching the build platform is run. To move
# to a new version, change the version in both URLs and take the checksums
# from
#   gh release view cargo-audit/v<version> --repo rustsec/rustsec --json assets
FROM ${RUST_IMAGE} AS cargo-audit-amd64
ADD --checksum=sha256:b77993532b253fcbf550996d7716465ec3d734d4e74e7f87bfb65a19add0fb59 \
    https://github.com/rustsec/rustsec/releases/download/cargo-audit%2Fv0.23.0/cargo-audit-x86_64-unknown-linux-gnu-v0.23.0.tgz \
    /tmp/cargo-audit.tgz

FROM ${RUST_IMAGE} AS cargo-audit-arm64
ADD --checksum=sha256:00eff3158429b9629abe8748e971f29f99ee53d4cff54a25072cbb15167bdda8 \
    https://github.com/rustsec/rustsec/releases/download/cargo-audit%2Fv0.23.0/cargo-audit-aarch64-unknown-linux-gnu-v0.23.0.tgz \
    /tmp/cargo-audit.tgz

# Checks Cargo.lock against the RustSec advisory database: known
# vulnerabilities fail the build, and so do warnings (unmaintained, unsound
# or yanked crates). It is a stage of its own, not part of `test`, because
# its result depends on the day it runs: a new advisory would otherwise fail
# a test run for code that hasn't changed. It needs the network, to fetch the
# database, and reads only the manifest and lockfile.
#
# Docker caches the result like any other step; to check against today's
# advisories, pass a new value: --build-arg RERUN=$(date +%s).
FROM cargo-audit-${TARGETARCH} AS audit
RUN tar -xzf /tmp/cargo-audit.tgz -C /usr/local/cargo/bin --strip-components=1 \
    && rm /tmp/cargo-audit.tgz \
    && cargo audit --version
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
ARG RERUN
RUN cargo audit --deny warnings

FROM ${RUST_IMAGE} AS toolchain
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
# so run it with `docker run -i`. Diagnostics go to stderr, and only when a
# profile is given after the image name (--diagnostics security). This is the last
# stage, so it is what a build without --target produces.
FROM ${RUNTIME_IMAGE} AS runtime
COPY --from=build /usr/local/bin/receiver /usr/local/bin/receiver
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/receiver"]
