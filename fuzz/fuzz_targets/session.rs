//! A session of correctly signed frames and key commands, steered by the
//! fuzz input, checked against a small model of the rules.
//!
//! Random bytes never get past the tag check, so this target signs its own
//! frames. After every step it checks that:
//! - a frame is accepted only with the right key, an unrevoked and unretired
//!   key id, and a seq above every seq ever accepted from that camera,
//!   restarts included (so a restart never lets an old frame back in);
//! - no queue holds more than `max_pending` frames;
//! - replay-state writes stay within the endurance budget.

#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_sensor_link::camera::Camera;
use secure_sensor_link::frame::{KEY_LEN, Key, compute_tag};
use secure_sensor_link::receiver::Receiver;
use serde_json::{Value, json};

const MAX_PENDING: u64 = 2;
const PERSIST_INTERVAL: u64 = 3;
const KEY_IDS: [u8; 4] = [0, 1, 2, 255];

fn key(camera: usize, key_id: u8) -> Key {
    [(camera as u8 + 1) * 16 + (key_id % 16); KEY_LEN]
}

/// Takes bytes from the fuzz input, and zeros once it runs out.
struct Input<'a>(std::slice::Iter<'a, u8>);

impl Input<'_> {
    fn byte(&mut self) -> u8 {
        self.0.next().copied().unwrap_or(0)
    }
}

#[derive(Default)]
struct CameraModel {
    provisioned: Vec<u8>,
    revoked: Vec<u8>,
    /// Highest key id an accepted frame has used.
    current_key: u8,
    /// Lowest and highest seq ever accepted, across restarts.
    accepted: Option<(u32, u32)>,
    /// Where the next frame's seq is chosen from.
    cursor: u32,
}

fn payload(input: &mut Input<'_>) -> (Vec<u8>, bool) {
    match input.byte() % 6 {
        0 | 1 => (vec![0], true),
        2 => (vec![1, 0, 0, 0, 9, 0, 0], true),
        3 => (vec![2], false),
        4 => (vec![], false),
        _ => {
            // A left spine; valid up to depth 64.
            let depth = usize::from(input.byte() % 80);
            let mut out = Vec::new();
            for i in 0..depth {
                out.push(1);
                out.extend_from_slice(&(i as i32).to_be_bytes());
            }
            out.extend(std::iter::repeat_n(0u8, depth + 1));
            (out, depth <= 64)
        }
    }
}

fn send(receiver: &mut Receiver, command: Value) -> Value {
    let response = receiver.handle_line(&command.to_string()).to_json();
    serde_json::from_str(&response).expect("a response is JSON")
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data.iter());
    let mut receiver = Receiver::new();
    let mut models = [CameraModel::default(), CameraModel::default()];
    for model in &mut models {
        model.provisioned.push(0);
    }
    let init = send(
        &mut receiver,
        json!({"command":"init","parameters":{
            "period_ms":50,"max_jitter_ms":5,"pair_window_ms":20,
            "max_pending":MAX_PENDING,"persist_interval":PERSIST_INTERVAL,
            "keys":{"cam1":hex::encode(key(0, 0)),"cam2":hex::encode(key(1, 0))}}}),
    );
    assert_eq!(init["status"], "ok");

    for _ in 0..64 {
        if input.0.len() == 0 {
            break;
        }
        let op = input.byte();
        let camera = usize::from(op >> 7);
        let name = ["cam1", "cam2"][camera];
        let key_id = KEY_IDS[usize::from(op >> 5) % KEY_IDS.len()];
        let model = &mut models[camera];
        match op % 8 {
            5 => {
                let response = send(
                    &mut receiver,
                    json!({"command":"add_key","parameters":{
                        "camera":name,"key_id":key_id,"key":hex::encode(key(camera, key_id))}}),
                );
                if response["status"] == "ok" && !model.provisioned.contains(&key_id) {
                    model.provisioned.push(key_id);
                }
                // A revoked id can never be provisioned again.
                assert!(!(model.revoked.contains(&key_id) && response["status"] == "ok"));
            }
            6 => {
                let response = send(
                    &mut receiver,
                    json!({"command":"revoke_key","parameters":{"camera":name,"key_id":key_id}}),
                );
                assert_eq!(response["status"] == "ok", model.provisioned.contains(&key_id));
                if response["status"] == "ok" && !model.revoked.contains(&key_id) {
                    model.revoked.push(key_id);
                }
            }
            7 => {
                assert_eq!(send(&mut receiver, json!({"command":"restart","parameters":{}}))["status"], "ok");
            }
            _ => {
                let seq = match input.byte() % 5 {
                    0 | 1 => model.cursor.wrapping_add(1),
                    2 => model.cursor,
                    3 => model.cursor.wrapping_add(u32::from(input.byte())),
                    _ => model.cursor.wrapping_sub(u32::from(input.byte() % 8)),
                };
                model.cursor = model.cursor.max(seq);
                let timestamp = match input.byte() {
                    255 => i64::MAX,
                    jitter => 1000 + i64::from(seq) * 50 + i64::from(jitter % 16) - 8,
                }
                .max(0);
                let version = if key_id == 0 && op & 0x10 == 0 { 1u8 } else { 2 };
                let right_key = input.byte() % 16 != 0;
                let signing_key = if right_key { key(camera, key_id) } else { [0xee; KEY_LEN] };
                let (payload, payload_valid) = payload(&mut input);

                let mut bytes = vec![version, camera as u8 + 1];
                if version == 2 {
                    bytes.push(key_id);
                }
                bytes.extend_from_slice(&seq.to_be_bytes());
                bytes.extend_from_slice(&timestamp.to_be_bytes());
                bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&payload);
                let tag = compute_tag(&signing_key, &bytes);
                bytes.extend_from_slice(&tag);

                let response = send(
                    &mut receiver,
                    json!({"command":"receive","parameters":{"frame":hex::encode(bytes)}}),
                );
                if response["status"] == "ok" {
                    assert!(right_key, "accepted a frame signed with the wrong key");
                    assert!(payload_valid, "accepted an invalid payload");
                    assert!(model.provisioned.contains(&key_id), "accepted an unprovisioned key");
                    assert!(!model.revoked.contains(&key_id), "accepted a revoked key");
                    assert!(key_id >= model.current_key, "accepted a retired key");
                    if let Some((_, highest)) = model.accepted {
                        assert!(seq > highest, "accepted seq {seq} at or below {highest}");
                    }
                    assert_eq!(response["payload"]["frame"]["seq"], seq);
                    model.current_key = key_id;
                    model.accepted = Some((model.accepted.map_or(seq, |(lowest, _)| lowest), seq));
                }
            }
        }

        let state = send(&mut receiver, json!({"command":"get_state","parameters":{}}));
        for (index, (name, camera)) in
            [("cam1", Camera::Cam1), ("cam2", Camera::Cam2)].into_iter().enumerate()
        {
            let pending = state["payload"]["cameras"][name]["pending"].as_array().expect("pending is a list");
            assert!(pending.len() as u64 <= MAX_PENDING, "{name} queue holds {}", pending.len());
            let writes = receiver.nvs().writes(camera).replay;
            let budget = models[index]
                .accepted
                .map_or(0, |(lowest, highest)| 1 + u64::from(highest - lowest) / PERSIST_INTERVAL);
            assert!(writes <= budget, "{name}: {writes} replay writes, budget {budget}");
        }
    }
});
