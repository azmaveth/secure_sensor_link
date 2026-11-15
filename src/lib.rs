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

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod camera;
pub mod command;
pub mod frame;
pub mod line_reader;
pub mod nvs;
pub mod receiver;
pub mod response;
pub mod sync;
pub mod tree;

use std::io::{self, BufRead, Write};
use std::panic::{self, AssertUnwindSafe};

use line_reader::{BoundedLines, Line, MAX_LINE_LEN};
use receiver::Receiver;
use response::Response;

/// Runs the receiver over `input` until end of input, writing one response
/// line per input line and flushing after each.
pub fn run<R: BufRead, W: Write>(input: R, mut output: W) -> io::Result<()> {
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
    }
    Ok(())
}
