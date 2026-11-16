//! Diagnostics profiles: which events, if any, are written to stderr.
//!
//! The profile is chosen when the receiver starts, with `--diagnostics`, and
//! never changes while it runs. The default writes nothing, so a deployment
//! gets diagnostics only by asking for them. Events never affect responses,
//! whatever the profile.

use std::ffi::OsString;
use std::str::FromStr;

use crate::event::Event;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Diagnostics {
    /// Nothing is written to stderr.
    #[default]
    Off,
    /// Only the events that bear on whether a camera's state can still be
    /// trusted (see [`Event::is_security`]). Each is caused by a
    /// key-management command or happens at most once per camera per boot,
    /// so link traffic can't turn them into a stream of log lines.
    Security,
    /// Every event, including tree sizes.
    All,
}

impl Diagnostics {
    /// The profile names, for messages.
    pub const NAMES: &str = "off, security, all";

    /// Whether this profile writes `event`.
    pub fn allows(self, event: &Event) -> bool {
        match self {
            Diagnostics::Off => false,
            Diagnostics::Security => event.is_security(),
            Diagnostics::All => true,
        }
    }
}

impl FromStr for Diagnostics {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, String> {
        match name {
            "off" => Ok(Diagnostics::Off),
            "security" => Ok(Diagnostics::Security),
            "all" => Ok(Diagnostics::All),
            other => Err(format!("unknown diagnostics profile {other:?} (expected one of: {})", Self::NAMES)),
        }
    }
}

/// What the command line asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invocation {
    Run(Diagnostics),
    Help,
}

pub const USAGE: &str = "\
Usage: receiver [--diagnostics <profile>]

Reads one JSON command per line on stdin and writes one response per line to
stdout. Diagnostic events, if enabled, go to stderr as JSON lines.

Options:
  --diagnostics <profile>  off       no diagnostics (default)
                           security  key and timestamp events only
                           all       every event, including tree sizes
  -h, --help               show this help
";

/// Parses the arguments after the program name. If `--diagnostics` is given
/// more than once, the last one applies.
pub fn parse_args<I: IntoIterator<Item = OsString>>(args: I) -> Result<Invocation, String> {
    let mut diagnostics = Diagnostics::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let arg = arg.to_str().ok_or("arguments must be valid UTF-8")?.to_owned();
        if arg == "-h" || arg == "--help" {
            return Ok(Invocation::Help);
        }
        let value = if arg == "--diagnostics" {
            let value = args.next().ok_or("--diagnostics needs a profile")?;
            value.to_str().ok_or("arguments must be valid UTF-8")?.to_owned()
        } else if let Some(value) = arg.strip_prefix("--diagnostics=") {
            value.to_owned()
        } else {
            return Err(format!("unknown argument {arg:?}"));
        };
        diagnostics = value.parse()?;
    }
    Ok(Invocation::Run(diagnostics))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Invocation, String> {
        parse_args(args.iter().map(OsString::from))
    }

    #[test]
    fn diagnostics_are_off_unless_asked_for() {
        assert_eq!(parse(&[]), Ok(Invocation::Run(Diagnostics::Off)));
        assert_eq!(parse(&["--diagnostics", "off"]), Ok(Invocation::Run(Diagnostics::Off)));
        assert_eq!(parse(&["--diagnostics", "security"]), Ok(Invocation::Run(Diagnostics::Security)));
        assert_eq!(parse(&["--diagnostics=all"]), Ok(Invocation::Run(Diagnostics::All)));
        assert_eq!(
            parse(&["--diagnostics=all", "--diagnostics", "off"]),
            Ok(Invocation::Run(Diagnostics::Off))
        );
    }

    #[test]
    fn help_and_bad_arguments() {
        assert_eq!(parse(&["--help"]), Ok(Invocation::Help));
        assert_eq!(parse(&["--diagnostics", "all", "-h"]), Ok(Invocation::Help));
        for bad in [
            &["--diagnostics"][..],
            &["--diagnostics", "loud"],
            &["--diagnostics="],
            &["--verbose"],
            &["all"],
        ] {
            assert!(parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_arguments_are_an_error_not_a_panic() {
        use std::os::unix::ffi::OsStringExt;
        assert!(parse_args([OsString::from_vec(vec![0xff])]).is_err());
        assert!(parse_args([OsString::from("--diagnostics"), OsString::from_vec(vec![0xff])]).is_err());
    }

    #[test]
    fn profiles_select_events() {
        let size = Event::TreeRejected {
            camera: "cam1",
            key_id: 0,
            seq: 1,
            nodes: 2000,
            depth: 11,
            limit_nodes: 1024,
            limit_depth: 64,
        };
        let key = Event::FinalKeyId { camera: "cam1", in_use: false };
        assert!(!Diagnostics::Off.allows(&size) && !Diagnostics::Off.allows(&key));
        assert!(!Diagnostics::Security.allows(&size) && Diagnostics::Security.allows(&key));
        assert!(Diagnostics::All.allows(&size) && Diagnostics::All.allows(&key));
    }
}
