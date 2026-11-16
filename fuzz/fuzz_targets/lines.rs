//! Arbitrary bytes on stdin after a valid `init`. The receiver must not
//! panic, must answer every line with exactly one line, and every answer
//! must be a response object.

#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_sensor_link::diagnostics::Diagnostics;
use serde_json::Value;

const INIT: &str = concat!(
    r#"{"command":"init","parameters":{"period_ms":50,"max_jitter_ms":5,"pair_window_ms":20,"#,
    r#""max_pending":4,"keys":{"#,
    r#""cam1":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","#,
    r#""cam2":"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"}}}"#,
    "\n"
);

fuzz_target!(|data: &[u8]| {
    let mut input = INIT.as_bytes().to_vec();
    input.extend_from_slice(data);
    let mut output = Vec::new();
    secure_sensor_link::run(input.as_slice(), &mut output, std::io::sink(), Diagnostics::All)
        .expect("reading and writing memory cannot fail");

    let newlines = data.iter().filter(|&&b| b == b'\n').count();
    let unterminated = usize::from(data.last().is_some_and(|&b| b != b'\n'));
    let output = String::from_utf8(output).expect("responses are UTF-8");
    let responses: Vec<&str> = output.lines().collect();
    assert_eq!(responses.len(), 1 + newlines + unterminated, "one response per line");

    for response in responses {
        let value: Value = serde_json::from_str(response).expect("a response is JSON");
        match value["status"].as_str() {
            Some("ok") => assert!(value["payload"].is_object()),
            Some("error") => assert!(value["payload"]["message"].is_string()),
            other => panic!("status {other:?}"),
        }
    }
});
