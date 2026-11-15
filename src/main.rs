//! `receiver`: reads commands from stdin, writes one response per line to
//! stdout, and writes diagnostic events as JSON lines to stderr.

use std::io::{self, BufWriter};
use std::process::ExitCode;

fn main() -> ExitCode {
    let input = io::stdin().lock();
    let output = BufWriter::new(io::stdout().lock());
    match secure_sensor_link::run(input, output, io::stderr()) {
        Ok(()) => ExitCode::SUCCESS,
        // Whoever reads stdout went away; there is no one left to answer.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("receiver: {e}");
            ExitCode::FAILURE
        }
    }
}
