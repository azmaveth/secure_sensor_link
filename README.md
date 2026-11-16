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
stdout. Diagnostics are off unless asked for; to turn them on, add the
profile after the image name (see [Diagnostics on stderr](#diagnostics-on-stderr)):

```bash
docker run --rm -i secure-sensor-link --diagnostics security < examples/spec_session.jsonl
```

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

Stdout carries only the responses, one per command. Diagnostic events are
separate: they go to stderr, one JSON object per line, and only if a
diagnostics profile turns them on. The profile is chosen when the receiver
starts and never affects a response.

| Profile | Writes | Meant for |
|---|---|---|
| `off` (default) | nothing | running exactly as the spec describes |
| `security` | `key_revoked`, `final_key_id`, `timestamp_beyond_i64` | deployment: the events that say whether a camera's state can still be trusted. Each is caused by a key-management command or happens at most once per camera per boot, so link traffic can't make them a stream of log lines |
| `all` | every event | bench and integration work: adds the tree-size events |

```bash
./target/release/receiver --diagnostics security < examples/spec_session.jsonl
```

`--diagnostics=security` works too, and `--help` lists the profiles. An
unknown profile or argument stops the receiver before it reads any input,
with exit status 2.

With the default profile nothing reports a revoked key's leftovers, the last
key id or an oversized timestamp. A deployment that wants those signals
should run with `security`.

Events are written to stderr by a separate thread, so the receiver never
waits on the log. If stderr is not being read (a pipe whose reader has
stalled), events queue up, and once a queue is full further ones are dropped.
Responses are never delayed.

- There are two queues of 1,024 lines. The `security` events have one to
  themselves and are written first. One boot can produce fewer than 520 of
  them, so no number of tree-size events can push one out; only many
  restarts while stderr stays blocked could fill that queue.
- When events are dropped, an `events_dropped` line says how many of each
  kind, as soon as stderr accepts a line again.
- At exit the receiver waits up to two seconds for queued events to be
  written.

| Event | When | Fields |
|---|---|---|
| `tree_rejected` | An authentic frame's tree breaks the 1,024-node or depth-64 limit, and its `seq` is higher than any already logged for that camera since the receiver started (so resending recorded frames adds no lines) | `camera`, `key_id`, `seq`, the tree's full `nodes` and `depth`, `limit_nodes`, `limit_depth` |
| `tree_size_record` | An accepted tree has more nodes, or more depth, than any earlier tree from that camera since the receiver started | `camera`, `key_id`, `seq`, the tree's `nodes` and `depth`, and the camera's `max_nodes_seen` and `max_depth_seen` |
| `key_revoked` | A key is revoked (not when it already was) | `camera`, `key_id`, and what the key leaves behind: `discarded` (its queued frames, dropped), `replay_bar` (the seq a frame must now exceed, if a frame from this key set it, else `null`), `set_timeline` (a frame from this key set the camera's timeline since the receiver started), `retired_keys` (unrevoked lower ids that stay retired because this is the highest key the camera has used) |
| `final_key_id` | Key id 255 is provisioned for a camera, or a camera moves to it | `camera`, `in_use`. Cameras only move forward through their keys, so a camera on 255 can't be re-keyed |
| `timestamp_beyond_i64` | An accepted frame's corrected timestamp is above 9223372036854775807 for the first time for that camera since the receiver started | `camera`, `key_id`, `seq`, `timestamp`. The value is exact and fits an unsigned 64-bit integer, but not a signed one. No real clock is near it, so the camera's timeline is following a bad timestamp |
| `events_dropped` | Events could not be written because stderr was not being read, and stderr now accepts lines again | `security` and `other`: how many of each kind were dropped. Written under any profile that is not `off` |

Revoking a key rejects its frames from then on and drops its queued ones. It
does not undo what earlier frames from that key did: the replay bar, the
timeline and the retirement of lower keys stay as they are. `key_revoked`
reports which of those the key touched. A `replay_bar` near 4294967295 means
the camera can no longer be accepted.

To keep them in a file:

```bash
./target/release/receiver --diagnostics all < examples/spec_session.jsonl 2> receiver.log
```

Events carry no timestamps (the receiver has no wall clock), so whatever
collects stderr should add them.

## Test

```bash
cargo test
```

| Suite | What it checks |
|---|---|
| unit tests in `src/` | frame layout, tree codec and limits, command validation, line reader, pairing, timestamp correction, command-line arguments, the log writer (order, security events first and never pushed out by others, a blocked or failing stream, dropped counts by kind) |
| `tests/spec_examples.rs` | all 24 steps of the spec's three example sessions, in-process and through the binary: with no arguments (stderr stays empty) and under each diagnostics profile (stdout unchanged); a bad command line is refused |
| `tests/protocol.rs` | one rule at a time: replay, tampering, malformed input, correction, sync, key rules, restarts, NVS write budget, oversized lines |
| `tests/size_logging.rs` | tree-size diagnostics: rejections report the full size, replayed oversized frames are logged once however many are cycled, records are logged once per camera, events go only to the log stream, and a failing log doesn't stop the receiver |
| `tests/key_events.rs` | key diagnostics: what a revoked key leaves behind (replay bar, timeline, retired keys, dropped frames), before and after a restart, and the last key id |
| `tests/diagnostics.rs` | diagnostics profiles: each writes its own events and the same responses, the log is never touched when off; the oversized-timestamp event fires once per camera per boot, and every timestamp fits an unsigned 64-bit integer; the binary keeps answering when nobody reads its stderr |
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

## Fuzzing

Four coverage-guided fuzz targets (libFuzzer) live in `fuzz/`, a package of
its own so that the receiver's dependencies stay as the spec limits them.

| Target | Input | What must hold |
|---|---|---|
| `frame` | arbitrary bytes, as a frame and as hex text | parsing never panics; an accepted frame has exactly the spec's layout |
| `tree` | arbitrary bytes as a payload | decoding never panics; an accepted tree is within the limits and encodes back to exactly the input; a tree rejected as too large is over a limit |
| `lines` | arbitrary bytes on stdin after a valid `init` | never panics; one response per line; every response is a well-formed response object |
| `session` | a session of correctly signed frames, key commands and restarts, steered by the input | a frame is accepted only with the right key, an unrevoked and unretired key id, a valid payload and a seq above every seq ever accepted from that camera, restarts included; queues stay within `max_pending`; replay writes stay within the endurance budget |

Run them all for 60 seconds each, one for longer, or all for longer:

```bash
./fuzz/run.sh
```

```bash
./fuzz/run.sh session 600
```

```bash
./fuzz/run.sh all 900
```

Each run starts from two sets of inputs. `fuzz/seeds/` is committed: the
spec's example frames, payloads and commands, so a run begins past the tag
check instead of at the first parse error. `fuzz/corpus/` is where libFuzzer
keeps every input that reached new code; it is not committed, and a later
run carries on from it.

This needs only the stable toolchain and a C++ compiler. The script passes
the coverage flags `cargo-fuzz` would, without a sanitizer: sanitizers need
a nightly toolchain, and the receiver has no `unsafe` code. Overflow checks
and debug assertions are on. A failing input is saved under
`fuzz/artifacts/<target>/`; to replay one:

```bash
./fuzz/target/*/release/session fuzz/artifacts/session/crash-<hash>
```

## Continuous integration

`.github/workflows/ci.yml` runs on every pull request, on `main`, and weekly:

| Job | What it runs |
|---|---|
| Format, lints and tests | the Docker `test` stage, then the runtime image on the spec's example session (one response per command, nothing on stderr) |
| Dependency advisories | the Docker `audit` stage, against the advisory database as it is at that moment |
| Fuzz targets | `./fuzz/run.sh`: each target for 60 seconds on a pull request or a push, and for 15 minutes on the weekly run. The corpus is carried from one run to the next, and any failing input is kept as a build artifact |

The weekly run is there so that a new advisory, or a fuzz failure that takes
longer to find, shows up without anyone pushing a change. Actions are pinned
by commit, as the Docker images are by digest.

## Code layout

| File | Role |
|---|---|
| `src/main.rs` | binary entry point: arguments, then stdin → `run` → stdout |
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
| `src/diagnostics.rs` | diagnostics profiles (`off`, `security`, `all`) and the `--diagnostics` argument |
| `src/log_writer.rs` | writes events on a separate thread through two bounded queues, security events first, so an unread stderr can't stop the receiver |
| `Dockerfile` | audit, toolchain, test, build and runtime stages, on images pinned by digest; `.dockerignore` sends the build only what it needs |
| `fuzz/` | fuzz targets, their seed inputs, and `run.sh`, which builds and runs them |
| `.github/workflows/ci.yml` | tests, dependency audit and a short fuzz run on every pull request and weekly |
