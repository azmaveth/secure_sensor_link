//! Secure Sensor Link receiver.
//!
//! Reads newline-delimited JSON commands, and decodes, authenticates,
//! timestamp-corrects and pairs camera frames from an untrusted link.
//!
//! Module map:
//! - [`line_reader`]: stdin lines with a hard length cap.
//! - [`command`]: JSON line to typed, range-checked [`command::Command`].
//! - [`frame`]: binary frame layout and HMAC verification.
//! - [`tree`]: payload tree decoding and level-order rendering.
//! - [`receiver`]: the state machine, including key rules and restarts.
//! - [`sync`]: pairing frames from the two cameras.
//! - [`nvs`]: the simulated non-volatile store that survives restarts.
//! - [`response`]: response JSON shapes.
//! - [`event`]: diagnostics for operators, written to stderr.
//! - [`diagnostics`]: which of those events are written; none by default.
//! - [`log_writer`]: where those events go. The binary writes them on a
//!   separate thread, so a log that isn't being read can't stop the receiver.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod camera;
pub mod command;
pub mod diagnostics;
pub mod event;
pub mod frame;
pub mod line_reader;
pub mod log_writer;
pub mod nvs;
pub mod receiver;
pub mod response;
pub mod sync;
pub mod tree;

use std::io::{self, BufRead, Write};
use std::panic::{self, AssertUnwindSafe};

use diagnostics::Diagnostics;
use line_reader::{BoundedLines, Line, MAX_LINE_LEN};
use log_writer::{EventSink, LineSink};
use receiver::Receiver;
use response::Response;

/// Runs the receiver over `input` until end of input, writing one response
/// line per input line to `output` and flushing after each. The diagnostic
/// events that `diagnostics` allows are written to `log`, one JSON line
/// each, on this thread; with [`Diagnostics::Off`] `log` is never written.
/// A failure to write the log is ignored: diagnostics must never stop the
/// receiver. For a `log` that can block, such as stderr when it is a pipe,
/// use [`run_with_sink`] and a [`log_writer::BackgroundLog`], as the binary
/// does.
pub fn run<R: BufRead, W: Write, L: Write>(
    input: R,
    output: W,
    log: L,
    diagnostics: Diagnostics,
) -> io::Result<()> {
    run_with_sink(input, output, LineSink(log), diagnostics)
}

/// As [`run`], sending the allowed diagnostic events to `sink`.
pub fn run_with_sink<R: BufRead, W: Write, S: EventSink>(
    input: R,
    mut output: W,
    mut sink: S,
    diagnostics: Diagnostics,
) -> io::Result<()> {
    let mut lines = BoundedLines::new(input, MAX_LINE_LEN);
    let mut receiver = Receiver::new();
    while let Some(line) = lines.next_line()? {
        let response = match line {
            // The receiver is written not to panic. This is a backstop so that
            // a bug fails one command instead of stopping the node.
            Line::Text(text) => panic::catch_unwind(AssertUnwindSafe(|| receiver.handle_line(&text)))
                .unwrap_or_else(|_| Response::error("internal error while handling command")),
            Line::TooLong => Response::error(format!("input line is longer than {MAX_LINE_LEN} bytes")),
            Line::NotUtf8 => Response::error("invalid JSON: input is not valid UTF-8"),
        };
        writeln!(output, "{}", response.to_json())?;
        output.flush()?;
        for event in receiver.take_events() {
            if diagnostics.allows(&event) {
                sink.emit(&event);
            }
        }
    }
    Ok(())
}
