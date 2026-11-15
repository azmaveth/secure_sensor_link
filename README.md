# Secure Sensor Link receiver

A Rust receiver that reads newline-delimited JSON commands on stdin, and
decodes, authenticates, timestamp-corrects and pairs camera frames. It covers
the base problem and both follow-ons (key rotation and revocation; restarts
with persistent replay protection).

Runtime dependencies are limited to what the spec allows: `serde` and
`serde_json` (JSON), `hex`, and `hmac` with `sha2` (HMAC-SHA256). `proptest`
is used only in tests.

## Build and run

Requires a stable Rust toolchain (edition 2024, Rust 1.85 or newer).

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

## Test

```bash
cargo test
```

| Suite | What it checks |
|---|---|
| unit tests in `src/` | frame layout, tree codec and limits, command validation, line reader, pairing, timestamp correction |
| `tests/spec_examples.rs` | all 24 steps of the spec's three example sessions, in-process and through the binary |
| `tests/protocol.rs` | one rule at a time: replay, tampering, malformed input, correction, sync, key rules, restarts, NVS write budget, oversized lines |
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
