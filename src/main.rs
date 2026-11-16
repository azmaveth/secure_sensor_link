//! `receiver`: reads commands from stdin and writes one response per line to
//! stdout. With `--diagnostics security` or `--diagnostics all` it also
//! writes diagnostic events as JSON lines to stderr; by default it doesn't.

use std::io::{self, BufWriter, Write};
use std::process::ExitCode;
use std::time::Duration;

use secure_sensor_link::diagnostics::{Diagnostics, Invocation, USAGE, parse_args};
use secure_sensor_link::log_writer::{BackgroundLog, DEFAULT_QUEUE_LINES};

/// Exit status for a command line that can't be understood.
const USAGE_ERROR: u8 = 2;

/// How long to wait at exit for queued diagnostics to reach stderr.
const LOG_DRAIN_GRACE: Duration = Duration::from_secs(2);

fn main() -> ExitCode {
    // Messages for the operator use `writeln!` with the result ignored:
    // `println!` and `eprintln!` panic if the stream is closed.
    let diagnostics = match parse_args(std::env::args_os().skip(1)) {
        Ok(Invocation::Run(diagnostics)) => diagnostics,
        Ok(Invocation::Help) => {
            let _ = write!(io::stdout(), "{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            let _ = write!(io::stderr(), "receiver: {message}\n\n{USAGE}");
            return ExitCode::from(USAGE_ERROR);
        }
    };
    let input = io::stdin().lock();
    let output = BufWriter::new(io::stdout().lock());
    let result = if diagnostics == Diagnostics::Off {
        secure_sensor_link::run(input, output, io::sink(), diagnostics)
    } else {
        // Events go to stderr through bounded queues and a writer thread,
        // so a stderr that nobody reads can't stop the receiver.
        let mut log = BackgroundLog::spawn(io::stderr(), DEFAULT_QUEUE_LINES);
        let result = secure_sensor_link::run_with_sink(input, output, &mut log, diagnostics);
        log.finish(LOG_DRAIN_GRACE);
        result
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        // Whoever reads stdout went away; there is no one left to answer.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(io::stderr(), "receiver: {e}");
            ExitCode::FAILURE
        }
    }
}
