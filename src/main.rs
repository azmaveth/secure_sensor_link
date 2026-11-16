//! `receiver`: reads commands from stdin and writes one response per line to
//! stdout. With `--diagnostics security` or `--diagnostics all` it also
//! writes diagnostic events as JSON lines to stderr; by default it doesn't.

use std::io::{self, BufWriter};
use std::process::ExitCode;

use secure_sensor_link::diagnostics::{Invocation, USAGE, parse_args};

/// Exit status for a command line that can't be understood.
const USAGE_ERROR: u8 = 2;

fn main() -> ExitCode {
    let diagnostics = match parse_args(std::env::args_os().skip(1)) {
        Ok(Invocation::Run(diagnostics)) => diagnostics,
        Ok(Invocation::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprint!("receiver: {message}\n\n{USAGE}");
            return ExitCode::from(USAGE_ERROR);
        }
    };
    let input = io::stdin().lock();
    let output = BufWriter::new(io::stdout().lock());
    match secure_sensor_link::run(input, output, io::stderr(), diagnostics) {
        Ok(()) => ExitCode::SUCCESS,
        // Whoever reads stdout went away; there is no one left to answer.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("receiver: {e}");
            ExitCode::FAILURE
        }
    }
}
