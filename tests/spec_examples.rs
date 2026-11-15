//! The three example sessions from the spec, replayed step by step.
//!
//! `tests/data/*.jsonl` holds `{"in": <command>, "out": <expected response>}`
//! per line, transcribed from the spec. Each follow-on example continues
//! from the state the previous one left.

use std::io::Write;
use std::process::{Command, Stdio};

use secure_sensor_link::receiver::Receiver;
use serde_json::Value;

const BASE: &str = include_str!("data/base.jsonl");
const FOLLOW_ON_1: &str = include_str!("data/followon1.jsonl");
const FOLLOW_ON_2: &str = include_str!("data/followon2.jsonl");

struct Step {
    input: String,
    expected: Value,
}

fn steps(transcripts: &[&str]) -> Vec<Step> {
    transcripts
        .iter()
        .flat_map(|t| t.lines())
        .map(|line| {
            let step: Value = serde_json::from_str(line).unwrap();
            Step { input: step["in"].to_string(), expected: step["out"].clone() }
        })
        .collect()
}

/// The base example was written before key rotation existed, so its
/// expected output has no `key_id` on frames and no `keys` in state. Drop
/// those two fields from the actual output wherever the expected output
/// lacks them; everything else must match exactly.
fn drop_follow_on_1_fields(actual: &mut Value, expected: &Value) {
    match (actual, expected) {
        (Value::Object(a), Value::Object(e)) => {
            for field in ["keys", "key_id"] {
                if !e.contains_key(field) {
                    a.remove(field);
                }
            }
            for (k, v) in a.iter_mut() {
                if let Some(ev) = e.get(k) {
                    drop_follow_on_1_fields(v, ev);
                }
            }
        }
        (Value::Array(a), Value::Array(e)) => {
            for (av, ev) in a.iter_mut().zip(e) {
                drop_follow_on_1_fields(av, ev);
            }
        }
        _ => {}
    }
}

fn check(steps: &[Step], outputs: &[String]) {
    assert_eq!(outputs.len(), steps.len(), "one response per command");
    for (i, (step, output)) in steps.iter().zip(outputs).enumerate() {
        let mut actual: Value = serde_json::from_str(output).unwrap();
        drop_follow_on_1_fields(&mut actual, &step.expected);
        assert_eq!(actual, step.expected, "step {i}: {}", step.input);
    }
}

fn run_in_process(steps: &[Step]) -> Vec<String> {
    let mut receiver = Receiver::new();
    steps.iter().map(|s| receiver.handle_line(&s.input).to_json()).collect()
}

#[test]
fn base_example() {
    let steps = steps(&[BASE]);
    check(&steps, &run_in_process(&steps));
}

#[test]
fn follow_on_1_example() {
    let steps = steps(&[BASE, FOLLOW_ON_1]);
    check(&steps, &run_in_process(&steps));
}

#[test]
fn follow_on_2_example() {
    let steps = steps(&[BASE, FOLLOW_ON_1, FOLLOW_ON_2]);
    check(&steps, &run_in_process(&steps));
}

/// The same sessions through the real binary over stdin and stdout. The
/// only diagnostic on stderr is cam1's first tree setting its size record.
#[test]
fn binary_reproduces_all_examples() {
    let steps = steps(&[BASE, FOLLOW_ON_1, FOLLOW_ON_2]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_receiver"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for step in &steps {
            writeln!(stdin, "{}", step.input).unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let lines: Vec<String> = String::from_utf8(output.stdout).unwrap().lines().map(String::from).collect();
    check(&steps, &lines);

    let log: Vec<Value> =
        String::from_utf8(output.stderr).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(
        log,
        vec![serde_json::json!({"event":"tree_size_record","camera":"cam1","key_id":0,"seq":1,
                                "nodes":5,"depth":3,"max_nodes_seen":5,"max_depth_seen":3})]
    );
}
