# Secure Sensor Link receiver

A Rust receiver that reads newline-delimited JSON commands on stdin, and
decodes, authenticates, timestamp-corrects and pairs camera frames. It covers
the base problem and both follow-ons (key rotation and revocation; restarts
with persistent replay protection).

Runtime dependencies are limited to what the spec allows: `serde` and
`serde_json` (JSON), `hex`, and `hmac` with `sha2` (HMAC-SHA256). `proptest`
is used only in tests.

## Build, test and run with Docker

No Rust toolchain is needed on the host, only Docker with BuildKit (the
default since Docker 23).

Run the formatting check, clippy and the full test suite:

```bash
docker build --target test --progress=plain .
```

Check the dependencies against the RustSec advisory database with
`cargo audit` (this one needs network access during the build):

```bash
docker build --target audit --build-arg RERUN=$(date +%s) --progress=plain .
```

The build fails on a known vulnerability, and on an unmaintained, unsound or
yanked crate. `RERUN` makes Docker run the check again instead of reusing an
earlier result, so it is always against today's advisories. It is separate
from the test stage so that a new advisory can't fail a test run for code
that hasn't changed.

Build the runtime image, then run the spec's example sessions through it:

```bash
docker build -t secure-sensor-link .
```

```bash
docker run --rm -i secure-sensor-link < examples/spec_session.jsonl
```

Keep `-i`: the receiver reads its commands from stdin. Responses go to
stdout and diagnostics to stderr, as below.

- Every image in the `Dockerfile` (the Rust toolchain, the Debian runtime
  base and the Dockerfile frontend) is pinned by digest, so a tag that is
  moved upstream can't change what gets built. To update one, look up the
  tag's current digest and replace it in the `Dockerfile`:

  ```bash
  docker buildx imagetools inspect rust:1.99-slim-trixie
  ```

- The toolchain image is Rust 1.99, the version the project is tested with.
  To check the minimum supported version instead:

  ```bash
  docker build --target test --build-arg RUST_IMAGE=rust:1.88-slim-trixie --progress=plain .
  ```

- Docker caches the test step like any other, so it won't run again if
  nothing changed. To force it while keeping the compiled dependencies:

  ```bash
  docker build --target test --build-arg RERUN=$(date +%s) --progress=plain .
  ```

  Avoid `--no-cache` for this: it also empties the build cache, so every
  dependency is compiled again.

- Downloaded crates and compiled dependencies are kept in BuildKit's cache
  between builds, so a rebuild after an edit only recompiles this crate.

## Build and run with Cargo

Requires Rust 1.88 or newer (edition 2024).

```bash
cargo build --release
```

Run the three example sessions from the spec:

```bash
./target/release/receiver < examples/spec_session.jsonl
```

Or type commands interactively. Each line gets exactly one response line:

```bash
./target/release/receiver
```

### Diagnostics on stderr

Stdout carries only the responses, one per command. Diagnostic events go to
stderr, one JSON object per line:

| Event | When | Fields |
|---|---|---|
| `tree_rejected` | An authentic frame's tree breaks the 1,024-node or depth-64 limit | `camera`, `key_id`, `seq`, the tree's full `nodes` and `depth`, `limit_nodes`, `limit_depth` |
| `tree_size_record` | An accepted tree has more nodes, or more depth, than any earlier tree from that camera since the receiver started | `camera`, `key_id`, `seq`, the tree's `nodes` and `depth`, and the camera's `max_nodes_seen` and `max_depth_seen` |

To keep them in a file:

```bash
./target/release/receiver < examples/spec_session.jsonl 2> receiver.log
```

Events carry no timestamps (the receiver has no wall clock), so whatever
collects stderr should add them.

## Test

```bash
cargo test
```

| Suite | What it checks |
|---|---|
| unit tests in `src/` | frame layout, tree codec and limits, command validation, line reader, pairing, timestamp correction |
| `tests/spec_examples.rs` | all 24 steps of the spec's three example sessions, in-process and through the binary |
| `tests/protocol.rs` | one rule at a time: replay, tampering, malformed input, correction, sync, key rules, restarts, NVS write budget, oversized lines |
| `tests/size_logging.rs` | tree-size diagnostics: rejections report the full size, a replayed oversized frame is logged once, records are logged once per camera, events go only to the log stream, and a failing log doesn't stop the receiver |
| `tests/properties.rs` | property tests: tree round trips, arbitrary bytes and lines never break the receiver, and over random sessions with restarts: restart safety, post-restart liveness, the NVS write budget and the queue bound |

`tests/data/*.jsonl` holds the spec examples as `{"in": …, "out": …}` pairs,
transcribed from the PDF. The base example predates key rotation, so its
expected output has no `key_id` or `keys`; the test ignores those two fields
there and nowhere else.

Lints and formatting:

```bash
cargo clippy --all-targets
```

```bash
cargo fmt --check
```

## Code layout

| File | Role |
|---|---|
| `src/main.rs` | binary entry point: stdin → `run` → stdout |
| `src/lib.rs` | `run`: the line loop, one response per line |
| `src/line_reader.rs` | reads lines with a hard length cap |
| `src/command.rs` | parses and range-checks a JSON command into `Command` |
| `src/frame.rs` | binary frame layout (v1 and v2) and HMAC verification |
| `src/tree.rs` | iterative preorder tree decoder with node and depth limits; level-order output |
| `src/receiver.rs` | state machine: frame check order, replay, correction, keys, restart |
| `src/sync.rs` | per-camera queues and pairing |
| `src/nvs.rs` | simulated non-volatile store; counts writes |
| `src/response.rs` | response JSON shapes |
| `src/event.rs` | diagnostic events written to stderr |
| `Dockerfile` | audit, toolchain, test, build and runtime stages, on images pinned by digest; `.dockerignore` sends the build only what it needs |
