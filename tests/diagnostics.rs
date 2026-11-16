//! Diagnostics profiles and the timestamp-width event.

mod common;

use common::*;
use secure_sensor_link::diagnostics::Diagnostics;
use secure_sensor_link::event::Event;
use serde_json::{Value, json};

/// A session that produces every kind of event: a size record, an oversized
/// tree, a timestamp above `i64::MAX`, the last key id, and a revocation.
fn session() -> String {
    [
        init_command(json!({})),
        receive_command(&frame(1, 1, i64::MAX).tree(&T::leaf(7)).hex()),
        receive_command(&frame(1, 2, 0).hex()),
        receive_command(&frame(1, 3, 0).tree(&T::spine(70)).hex()),
        json!({"command":"add_key","parameters":{"camera":"cam2","key_id":255,"key":hex::encode(key(0x40))}})
            .to_string(),
        json!({"command":"revoke_key","parameters":{"camera":"cam1","key_id":0}}).to_string(),
    ]
    .join("\n")
}

fn run(diagnostics: Diagnostics) -> (Vec<Value>, Vec<String>) {
    let (mut out, mut log) = (Vec::new(), Vec::new());
    secure_sensor_link::run(session().as_bytes(), &mut out, &mut log, diagnostics).unwrap();
    let parse = |bytes: Vec<u8>| -> Vec<Value> {
        String::from_utf8(bytes).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    };
    let events = parse(log).iter().map(|e| e["event"].as_str().unwrap().to_owned()).collect();
    (parse(out), events)
}

#[test]
fn each_profile_writes_its_own_events_and_the_same_responses() {
    let (responses_off, events_off) = run(Diagnostics::Off);
    let (responses_security, events_security) = run(Diagnostics::Security);
    let (responses_all, events_all) = run(Diagnostics::All);

    assert_eq!(events_off, Vec::<String>::new());
    assert_eq!(events_security, ["timestamp_beyond_i64", "final_key_id", "key_revoked"]);
    assert_eq!(
        events_all,
        ["tree_size_record", "timestamp_beyond_i64", "tree_rejected", "final_key_id", "key_revoked"]
    );

    assert_eq!(responses_off.len(), 6);
    assert_eq!(responses_off, responses_security);
    assert_eq!(responses_off, responses_all);
}

#[test]
fn the_default_profile_is_off() {
    assert_eq!(Diagnostics::default(), Diagnostics::Off);
}

/// A log stream that fails the test if anything touches it.
struct Untouched;

impl std::io::Write for Untouched {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        panic!("the log was written with diagnostics off");
    }
    fn flush(&mut self) -> std::io::Result<()> {
        panic!("the log was flushed with diagnostics off");
    }
}

#[test]
fn with_diagnostics_off_the_log_is_never_touched() {
    let mut out = Vec::new();
    secure_sensor_link::run(session().as_bytes(), &mut out, Untouched, Diagnostics::Off).unwrap();
    assert_eq!(String::from_utf8(out).unwrap().lines().count(), 6);
}

fn beyond(camera: &'static str, seq: u32, timestamp: i128) -> Event {
    Event::TimestampBeyondI64 { camera, key_id: 0, seq, timestamp }
}

#[test]
fn a_timestamp_above_signed_64_bits_is_flagged_once_per_camera_per_boot() {
    let mut rx = Rx::new(json!({}));
    let max = i128::from(i64::MAX);

    // The largest signed 64-bit value itself is not beyond it.
    rx.accept(&frame(1, 1, i64::MAX));
    assert_eq!(rx.receiver.take_events(), vec![]);

    // The next frame is corrected to one period later, which is.
    let p = rx.accept(&frame(1, 2, 0));
    assert_eq!(p["frame"]["timestamp"].to_string(), (max + 50).to_string());
    assert_eq!(rx.receiver.take_events(), vec![beyond("cam1", 2, max + 50)]);
    rx.accept(&frame(1, 3, 0));
    assert_eq!(rx.receiver.take_events(), vec![], "flagged once");

    // Each camera is flagged separately.
    rx.accept(&frame(2, 1, i64::MAX));
    rx.accept(&frame(2, 5, 0));
    assert_eq!(rx.receiver.take_events(), vec![beyond("cam2", 5, max + 200)]);

    // A restart starts the timeline over, and the flag with it.
    rx.restart();
    rx.accept(&frame(1, 200, i64::MAX));
    rx.accept(&frame(1, 201, 0));
    assert_eq!(rx.receiver.take_events(), vec![beyond("cam1", 201, max + 50)]);
}

#[test]
fn every_timestamp_fits_an_unsigned_64_bit_integer() {
    // The furthest a timeline can get: it starts at the largest timestamp a
    // frame can carry, and is extended across the whole sequence range at
    // the longest period.
    let mut rx = Rx::new(json!({"period_ms": 60_000, "max_jitter_ms": 0, "pair_window_ms": 0}));
    rx.accept(&frame(1, 0, i64::MAX));
    let p = rx.accept(&frame(1, u32::MAX, 0));
    let largest = i128::from(i64::MAX) + i128::from(u32::MAX) * 60_000;
    assert_eq!(p["frame"]["timestamp"].to_string(), largest.to_string());
    assert!(largest <= i128::from(u64::MAX));
    assert_eq!(p["frame"]["timestamp"].as_u64(), Some(largest as u64), "parses as u64");
}

/// Runs the real binary on `input` without reading its stderr until it has
/// exited, as if stderr were a pipe that nobody drains. Returns the number
/// of responses and whatever reached stderr.
fn run_with_unread_stderr(profile: &str, input: String) -> (usize, String) {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    let mut child = Command::new(env!("CARGO_BIN_EXE_receiver"))
        .args(["--diagnostics", profile])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let feeder = std::thread::spawn(move || {
        // If the receiver stopped reading, this write would never finish.
        stdin.write_all(input.as_bytes()).unwrap();
    });
    let mut stdout = String::new();
    child.stdout.take().unwrap().read_to_string(&mut stdout).unwrap();
    feeder.join().unwrap();
    assert!(child.wait().unwrap().success());
    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
    (stdout.lines().count(), stderr)
}

#[test]
fn a_log_that_nobody_reads_does_not_stop_the_receiver() {
    // 3,000 oversized trees with rising seqs: one `tree_rejected` event
    // each, several times what a pipe holds. Written straight to stderr,
    // the receiver would block part-way and this test would hang.
    let frames = 3000;
    let tree = T::spine(70);
    let mut input = init_command(json!({}));
    for seq in 1..=frames {
        input.push('\n');
        input.push_str(&receive_command(&frame(1, seq, 0).tree(&tree).hex()));
    }
    let (responses, stderr) = run_with_unread_stderr("all", input);
    assert_eq!(responses, frames as usize + 1, "every command was answered");

    // Some events were written and the rest dropped; none was half-written.
    let events = stderr.lines().count();
    assert!(events > 0 && events < frames as usize, "{events} events");
    assert!(stderr.lines().all(|l| serde_json::from_str::<Value>(l).is_ok()));
}
