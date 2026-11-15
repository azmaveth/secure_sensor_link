//! Behaviour tests, one rule at a time.

mod common;

use common::*;
use secure_sensor_link::camera::Camera;
use serde_json::{Value, json};

fn no_overrides() -> Value {
    json!({})
}

// ---------------------------------------------------------------- lifecycle

#[test]
fn every_command_before_init_is_rejected() {
    let mut rx = Rx { receiver: secure_sensor_link::receiver::Receiver::new() };
    for line in [
        r#"{"command":"get_state","parameters":{}}"#.to_owned(),
        r#"{"command":"restart","parameters":{}}"#.to_owned(),
        r#"{"command":"revoke_key","parameters":{"camera":"cam1","key_id":0}}"#.to_owned(),
        receive_command(&frame(1, 1, 0).hex()),
    ] {
        assert!(rx.err(&line).contains("not initialized"));
    }
}

#[test]
fn failed_init_leaves_receiver_uninitialized() {
    let mut rx = Rx { receiver: secure_sensor_link::receiver::Receiver::new() };
    rx.err(&init_command(json!({"max_pending": 0})));
    rx.ok(&init_command(no_overrides()));
    assert!(rx.err(&init_command(no_overrides())).contains("already initialized"));
}

// ---------------------------------------------------------------- acceptance

#[test]
fn accepted_frame_is_reported_with_its_tree() {
    let mut rx = Rx::new(no_overrides());
    let tree =
        T::Node(1, Box::new(T::leaf(2)), Box::new(T::Node(3, Box::new(T::leaf(4)), Box::new(T::leaf(5)))));
    let payload = rx.accept(&frame(1, 7, 1000).tree(&tree));
    assert_eq!(
        payload["frame"],
        json!({"camera":"cam1","key_id":0,"seq":7,"timestamp":1000,"corrected":false,"tree":[1,2,3,null,null,4,5]})
    );
}

#[test]
fn uppercase_hex_is_accepted() {
    let mut rx = Rx::new(no_overrides());
    rx.ok(&receive_command(&frame(1, 1, 0).hex().to_uppercase()));
}

#[test]
fn replayed_and_older_frames_are_rejected() {
    let mut rx = Rx::new(no_overrides());
    rx.accept(&frame(1, 5, 1000));
    assert_eq!(rx.reject(&frame(1, 5, 1000)), "stale or replayed frame: cam1 seq 5");
    assert_eq!(rx.reject(&frame(1, 4, 950)), "stale or replayed frame: cam1 seq 4");
    // Replay protection is per camera.
    rx.accept(&frame(2, 5, 1000));
}

#[test]
fn seq_zero_and_seq_max_are_usable() {
    let mut rx = Rx::new(no_overrides());
    rx.accept(&frame(1, 0, 0));
    rx.accept(&frame(1, u32::MAX, 0));
    rx.reject(&frame(1, u32::MAX, 0));
}

#[test]
fn tampered_frames_fail_authentication_and_change_nothing() {
    let mut rx = Rx::new(no_overrides());
    rx.accept(&frame(1, 1, 1000));
    let before = rx.state();

    let mut bytes = frame(1, 2, 1050).bytes();
    bytes[5] ^= 0x01; // seq
    assert_eq!(rx.err(&receive_command(&hex::encode(&bytes))), "authentication failed for cam1");

    // Signed with the other camera's key.
    let mut wrong_key = frame(1, 2, 1050);
    wrong_key.key = cam2_key();
    assert_eq!(rx.reject(&wrong_key), "authentication failed for cam1");

    assert_eq!(rx.state(), before);
    rx.accept(&frame(1, 2, 1050));
}

#[test]
fn malformed_frames_are_rejected() {
    let mut rx = Rx::new(no_overrides());
    let mut cases = vec![
        "zz".to_owned(),
        "0".to_owned(),
        String::new(),
        hex::encode([1u8; 10]),
        frame(1, 1, -1).hex(),
        {
            let mut f = frame(1, 1, 0).bytes();
            f[0] = 3;
            hex::encode(f)
        },
        {
            let mut f = frame(1, 1, 0).bytes();
            f[1] = 9;
            hex::encode(f)
        },
        {
            let mut f = frame(1, 1, 0).bytes();
            f.push(0);
            hex::encode(f)
        },
    ];
    cases.push("00".repeat(200_000));
    for case in cases {
        let message = rx.err(&receive_command(&case));
        assert!(message.starts_with("malformed frame: "), "{message}");
    }
}

#[test]
fn authentic_frame_with_invalid_tree_is_rejected_without_consuming_its_seq() {
    let mut rx = Rx::new(no_overrides());
    for payload in [vec![], vec![0, 0], vec![2], vec![1, 0, 0, 0]] {
        let message = rx.reject(&frame(1, 3, 1000).payload(payload));
        assert!(message.starts_with("malformed frame: invalid tree"), "{message}");
    }
    assert_eq!(rx.state()["cameras"]["cam1"]["last_seq"], Value::Null);
    rx.accept(&frame(1, 3, 1000));
}

#[test]
fn tree_limits_are_enforced_through_receive() {
    let mut rx = Rx::new(no_overrides());
    let spine =
        |depth: usize| (0..depth).fold(T::Nil, |t, i| T::Node(i as i32, Box::new(t), Box::new(T::Nil)));
    rx.accept(&frame(1, 1, 0).tree(&spine(64)));
    assert!(rx.reject(&frame(1, 2, 50).tree(&spine(65))).contains("deeper than 64"));
}

// ---------------------------------------------------------------- timestamps

#[test]
fn timestamps_outside_jitter_are_replaced_by_the_expected_value() {
    let mut rx = Rx::new(no_overrides());
    rx.accept(&frame(1, 10, 1000));
    // Skipped seqs still advance the expected timestamp (1150 here).
    let p = rx.accept(&frame(1, 13, 1155));
    assert_eq!(p["frame"]["corrected"], false, "5 ms off is within the jitter bound");
    let mut rx = Rx::new(no_overrides());
    rx.accept(&frame(1, 10, 1000));
    let p = rx.accept(&frame(1, 13, 1156));
    assert_eq!(
        (p["frame"]["timestamp"].clone(), p["frame"]["corrected"].clone()),
        (json!(1150), json!(true))
    );
    // The corrected value is the new baseline.
    let p = rx.accept(&frame(1, 14, 1203));
    assert_eq!(
        (p["frame"]["timestamp"].clone(), p["frame"]["corrected"].clone()),
        (json!(1203), json!(false))
    );
    assert_eq!(rx.state()["cameras"]["cam1"]["last_timestamp"], 1203);
}

#[test]
fn timestamp_arithmetic_is_exact_beyond_64_bits() {
    let mut rx = Rx::new(json!({"period_ms": 60000, "max_jitter_ms": 0, "pair_window_ms": 0}));
    rx.accept(&frame(1, 0, i64::MAX));
    let out = rx.raw(&receive_command(&frame(1, u32::MAX, 0).hex()));
    let expected = i128::from(i64::MAX) + i128::from(u32::MAX) * 60_000;
    assert!(out.contains(&format!("\"timestamp\":{expected},\"corrected\":true")), "{out}");
}

// ---------------------------------------------------------------- sync

#[test]
fn full_queue_releases_its_oldest_frame() {
    let mut rx = Rx::new(json!({"max_pending": 2}));
    rx.accept(&frame(1, 1, 1000));
    rx.accept(&frame(1, 2, 1050));
    let p = rx.accept(&frame(1, 3, 1100));
    assert_eq!(p["synced"], json!([{"timestamp":1000,"cam1":1,"cam2":null}]));
    assert_eq!(rx.state()["cameras"]["cam1"]["pending"], json!([2, 3]));
}

#[test]
fn a_late_frame_drains_everything_older_than_it() {
    let mut rx = Rx::new(no_overrides());
    for seq in 1..=3 {
        rx.accept(&frame(1, seq, 1000 + 50 * i64::from(seq)));
    }
    let p = rx.accept(&frame(2, 3, 1152));
    assert_eq!(
        p["synced"],
        json!([
            {"timestamp":1050,"cam1":1,"cam2":null},
            {"timestamp":1100,"cam1":2,"cam2":null},
            {"timestamp":1151,"cam1":3,"cam2":3},
        ])
    );
}

#[test]
fn wide_window_pairs_greedily_with_the_oldest_candidate() {
    // cam2's two frames are both within 49 ms of cam1's frame; the oldest
    // head in the queue wins, as the pairing rule is applied in order.
    let mut rx = Rx::new(json!({"pair_window_ms": 49}));
    rx.accept(&frame(2, 1, 1000));
    rx.accept(&frame(2, 2, 1050));
    let p = rx.accept(&frame(1, 1, 1030));
    assert_eq!(p["synced"], json!([{"timestamp":1015,"cam1":1,"cam2":1}]));
    assert_eq!(rx.state()["cameras"]["cam2"]["pending"], json!([2]));
}

// ---------------------------------------------------------------- keys

#[test]
fn version_2_frames_use_their_key_id() {
    let mut rx = Rx::new(no_overrides());
    rx.accept(&frame(1, 1, 0).v2(0, cam1_key()));
    assert_eq!(rx.reject(&frame(1, 2, 50).v2(3, key(0x99))), "cam1 key 3 is not provisioned");
    assert_eq!(rx.add_key("cam1", 3, key(0x99))["status"], "ok");
    let p = rx.accept(&frame(1, 2, 50).v2(3, key(0x99)));
    assert_eq!(p["frame"]["key_id"], 3);
    assert_eq!(rx.reject(&frame(1, 3, 100)), "cam1 key 0 is retired");
}

#[test]
fn provisioning_a_key_does_not_retire_older_keys_until_it_is_used() {
    let mut rx = Rx::new(no_overrides());
    rx.add_key("cam1", 1, key(0x40));
    rx.accept(&frame(1, 1, 0));
    rx.accept(&frame(1, 2, 50).v2(1, key(0x40)));
    rx.reject(&frame(1, 3, 100));
}

#[test]
fn readding_an_identical_key_is_a_no_op() {
    let mut rx = Rx::new(no_overrides());
    assert_eq!(rx.add_key("cam1", 1, key(0x40))["status"], "ok");
    let writes = rx.receiver.nvs().writes(Camera::Cam1).keys;
    assert_eq!(rx.add_key("cam1", 1, key(0x40))["status"], "ok");
    assert_eq!(rx.add_key("cam1", 0, cam1_key())["status"], "ok");
    assert_eq!(rx.receiver.nvs().writes(Camera::Cam1).keys, writes);
}

#[test]
fn add_key_rejects_conflicting_revoked_and_stale_ids() {
    let mut rx = Rx::new(no_overrides());
    let conflict = rx.add_key("cam1", 0, key(0x77));
    assert!(conflict["payload"]["message"].as_str().unwrap().contains("already provisioned"));

    rx.revoke_key("cam2", 0);
    let revoked = rx.add_key("cam2", 0, cam2_key());
    assert!(revoked["payload"]["message"].as_str().unwrap().contains("revoked"));

    rx.add_key("cam1", 5, key(0x50));
    rx.accept(&frame(1, 1, 0).v2(5, key(0x50)));
    let stale = rx.add_key("cam1", 2, key(0x60));
    assert!(stale["payload"]["message"].as_str().unwrap().contains("would be retired"));

    // None of the failures changed the key list.
    assert_eq!(
        rx.state()["cameras"]["cam1"]["keys"],
        json!([{"key_id":0,"status":"retired"},{"key_id":5,"status":"active"}])
    );
}

#[test]
fn revoke_key_errors_and_idempotence() {
    let mut rx = Rx::new(no_overrides());
    assert_eq!(rx.revoke_key("cam2", 7)["payload"]["message"], "cam2 key 7 is not provisioned");
    let first = rx.revoke_key("cam2", 0);
    let writes = rx.receiver.nvs().writes(Camera::Cam2).keys;
    assert_eq!(rx.revoke_key("cam2", 0), first);
    assert_eq!(rx.receiver.nvs().writes(Camera::Cam2).keys, writes);
}

#[test]
fn revoking_a_key_discards_queued_frames_it_authenticated() {
    let mut rx = Rx::new(no_overrides());
    rx.add_key("cam1", 1, key(0x40));
    rx.accept(&frame(1, 1, 1000));
    rx.accept(&frame(1, 2, 1050).v2(1, key(0x40)));
    assert_eq!(rx.state()["cameras"]["cam1"]["pending"], json!([1, 2]));

    let p = rx.ok(&json!({"command":"revoke_key","parameters":{"camera":"cam1","key_id":1}}).to_string());
    assert_eq!(p["cameras"]["cam1"]["pending"], json!([1]));
    // Replay state is untouched: seq 2 stays consumed.
    assert_eq!(p["cameras"]["cam1"]["last_seq"], 2);
}

// ---------------------------------------------------------------- restarts

#[test]
fn restart_wipes_memory_but_keeps_config_and_keys() {
    let mut rx = Rx::new(no_overrides());
    rx.add_key("cam1", 1, key(0x40));
    rx.accept(&frame(1, 1, 1000).v2(1, key(0x40)));
    rx.revoke_key("cam2", 0);
    let state = rx.restart();
    assert_eq!(
        state["cameras"]["cam1"],
        json!({"last_seq":null,"last_timestamp":null,"pending":[],
               "keys":[{"key_id":0,"status":"retired"},{"key_id":1,"status":"active"}]})
    );
    assert_eq!(state["cameras"]["cam2"]["keys"], json!([{"key_id":0,"status":"revoked"}]));
    assert!(rx.err(&init_command(no_overrides())).contains("already initialized"));
    assert_eq!(rx.reject(&frame(1, 500, 0)), "cam1 key 0 is retired");
}

#[test]
fn after_restart_the_reserved_window_is_rejected_and_beyond_it_accepted() {
    let mut rx = Rx::new(json!({"persist_interval": 10}));
    for seq in 1..=25 {
        rx.accept(&frame(1, seq, 50 * i64::from(seq)));
    }
    rx.restart();
    // Floor writes happened at seqs 1, 12 and 23, so the floor is 33.
    // Everything up to 33 is refused; the spec only requires accepting
    // seq > S + persist_interval = 35, and 34 is accepted too.
    for seq in [1, 25, 26, 33] {
        assert_eq!(rx.reject(&frame(1, seq, 0)), format!("stale or replayed frame: cam1 seq {seq}"));
    }
    let p = rx.accept(&frame(1, 34, 99_999));
    assert_eq!(p["frame"]["timestamp"], 99_999, "timeline starts over");
    assert_eq!(p["frame"]["corrected"], false);
}

#[test]
fn queued_frames_are_discarded_by_a_restart() {
    let mut rx = Rx::new(no_overrides());
    rx.accept(&frame(1, 1, 1000));
    rx.restart();
    let p = rx.accept(&frame(2, 200, 1000));
    assert_eq!(p["synced"], json!([]));
}

#[test]
fn restart_before_any_frame_accepts_from_the_start() {
    let mut rx = Rx::new(no_overrides());
    rx.restart();
    rx.accept(&frame(1, 0, 0));
}

#[test]
fn huge_persist_interval_does_not_overflow() {
    let mut rx = Rx::new(json!({"persist_interval": u32::MAX}));
    rx.accept(&frame(1, 5, 0));
    rx.accept(&frame(1, 6, 50));
    rx.restart();
    // S + persist_interval exceeds every possible seq, so nothing is owed.
    rx.reject(&frame(1, u32::MAX, 0));
    assert_eq!(rx.receiver.nvs().writes(Camera::Cam1).replay, 1);
}

#[test]
fn replay_writes_stay_within_the_endurance_budget() {
    for interval in [1u32, 2, 7, 100] {
        let mut rx = Rx::new(json!({ "persist_interval": interval }));
        let (s_min, s_max) = (3u32, 1_000u32);
        for seq in s_min..=s_max {
            rx.accept(&frame(1, seq, 50 * i64::from(seq)));
        }
        let budget = 1 + u64::from(s_max - s_min) / u64::from(interval);
        let writes = rx.receiver.nvs().writes(Camera::Cam1).replay;
        assert!(writes <= budget, "interval {interval}: {writes} writes, budget {budget}");
    }
}

// ---------------------------------------------------------------- input lines

fn run_lines(input: &[u8]) -> Vec<Value> {
    let mut out = Vec::new();
    secure_sensor_link::run(input, &mut out).unwrap();
    String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

#[test]
fn every_input_line_gets_exactly_one_response() {
    let mut input = Vec::new();
    input.extend_from_slice(b"\n");
    input.extend_from_slice(b"\xff\n");
    input.extend_from_slice(&vec![b'x'; 2_000_000]);
    input.extend_from_slice(b"\n");
    input.extend_from_slice(init_command(no_overrides()).as_bytes());
    input.extend_from_slice(b"\r\n{\"command\":\"get_state\"}");
    let responses = run_lines(&input);
    let statuses: Vec<&str> = responses.iter().map(|r| r["status"].as_str().unwrap()).collect();
    assert_eq!(statuses, ["error", "error", "error", "ok", "ok"]);
    assert!(responses[2]["payload"]["message"].as_str().unwrap().contains("longer than"));
}

#[test]
fn largest_possible_frame_fits_on_a_line() {
    let payload_len = usize::from(u16::MAX);
    // A tree followed by padding is invalid, but only after the length,
    // authentication and line-length checks have all passed.
    let payload = vec![0u8; payload_len];
    let line = receive_command(&frame(1, 1, 0).v2(0, cam1_key()).payload(payload).hex());
    let mut input = init_command(no_overrides()).into_bytes();
    input.push(b'\n');
    input.extend_from_slice(line.as_bytes());
    let responses = run_lines(&input);
    assert!(responses[1]["payload"]["message"].as_str().unwrap().contains("invalid tree"));
}
