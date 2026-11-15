//! Property tests: hostile input never breaks the receiver, and the restart
//! and endurance rules hold over random sessions.

mod common;

use common::*;
use proptest::prelude::*;
use secure_sensor_link::camera::Camera;
use secure_sensor_link::receiver::Receiver;
use secure_sensor_link::tree;
use serde_json::{Value, json};

fn arb_tree() -> impl Strategy<Value = T> {
    let leaf = prop_oneof![1 => Just(T::Nil), 3 => any::<i32>().prop_map(T::leaf)];
    leaf.prop_recursive(12, 200, 2, |inner| {
        prop_oneof![
            1 => Just(T::Nil),
            4 => (any::<i32>(), inner.clone(), inner).prop_map(|(v, l, r)| T::Node(v, Box::new(l), Box::new(r))),
        ]
    })
}

/// One step of a random session.
#[derive(Debug, Clone)]
enum Op {
    Receive { camera: u8, seq: u32, jitter: i64, tamper: bool },
    Restart,
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        12 => (1u8..=2, 0u32..400, -20i64..20, prop::bool::weighted(0.1))
            .prop_map(|(camera, seq, jitter, tamper)| Op::Receive { camera, seq, jitter, tamper }),
        1 => Just(Op::Restart),
    ]
}

fn status(response: &str) -> Value {
    serde_json::from_str::<Value>(response).unwrap()["status"].clone()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn tree_round_trips(t in arb_tree()) {
        let decoded = tree::decode(&t.encode());
        prop_assume!(decoded.as_ref().is_ok_and(|d| d.len() <= tree::MAX_NODES));
        prop_assert_eq!(decoded.unwrap().level_order(), t.level_order());
    }

    #[test]
    fn arbitrary_payload_bytes_never_panic(payload in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = tree::decode(&payload);
    }

    #[test]
    fn arbitrary_lines_get_one_well_formed_response(line in "\\PC{0,200}") {
        let mut rx = Rx::new(json!({}));
        let response = rx.raw(&line);
        let status = status(&response);
        prop_assert!(status == "ok" || status == "error");
    }

    #[test]
    fn arbitrary_frame_bytes_are_handled(bytes in prop::collection::vec(any::<u8>(), 0..120)) {
        let mut rx = Rx::new(json!({}));
        let response = rx.send(&receive_command(&hex::encode(&bytes)));
        prop_assert_eq!(&response["status"], "error");
    }

    /// Runs the same random session through a receiver that restarts (B)
    /// and one that never does (A), checking:
    /// - safety: B never accepts a frame A rejects;
    /// - liveness: after a restart, B accepts a valid frame whose seq is
    ///   more than persist_interval past everything B accepted before;
    /// - endurance: B's replay writes stay within the NVS budget;
    /// - queues never exceed max_pending.
    #[test]
    fn restarts_are_safe_live_and_within_budget(
        ops in prop::collection::vec(arb_op(), 1..120),
        interval in 1u32..30,
        max_pending in 1u32..5,
    ) {
        let overrides = json!({"persist_interval": interval, "max_pending": max_pending});
        let mut a = Receiver::new();
        let mut b = Receiver::new();
        a.handle_line(&init_command(overrides.clone()));
        b.handle_line(&init_command(overrides));

        // Highest seq B accepted before its latest restart, and overall
        // min/max of B's accepted seqs, per camera (index 0 = cam1).
        let mut before_restart: [Option<u32>; 2] = [None, None];
        let mut since_restart: [Option<u32>; 2] = [None, None];
        let mut accepted_range: [Option<(u32, u32)>; 2] = [None, None];

        for op in ops {
            match op {
                Op::Restart => {
                    b.handle_line(r#"{"command":"restart","parameters":{}}"#);
                    for i in 0..2 {
                        before_restart[i] = before_restart[i].max(since_restart[i]);
                        since_restart[i] = None;
                    }
                }
                Op::Receive { camera, seq, jitter, tamper } => {
                    let mut f = frame(camera, seq, 50 * i64::from(seq) + 1000 + jitter);
                    if tamper {
                        f.key = key(0xee);
                    }
                    let line = receive_command(&f.hex());
                    let a_ok = status(&a.handle_line(&line).to_json()) == "ok";
                    let b_ok = status(&b.handle_line(&line).to_json()) == "ok";
                    let i = usize::from(camera - 1);

                    prop_assert!(!b_ok || a_ok, "B accepted {:?} that A rejected", f);
                    let owed = before_restart[i].max(since_restart[i])
                        .is_none_or(|s| u64::from(seq) > u64::from(s) + u64::from(interval));
                    if !tamper && since_restart[i].is_none() && owed {
                        prop_assert!(b_ok, "B refused seq {} it must accept", seq);
                    }
                    if b_ok {
                        since_restart[i] = Some(seq);
                        accepted_range[i] = Some(match accepted_range[i] {
                            None => (seq, seq),
                            Some((lo, hi)) => (lo.min(seq), hi.max(seq)),
                        });
                    }
                }
            }
            let state: Value = serde_json::from_str(&b.handle_line(r#"{"command":"get_state"}"#).to_json()).unwrap();
            for cam in ["cam1", "cam2"] {
                let pending = state["payload"]["cameras"][cam]["pending"].as_array().unwrap().len();
                prop_assert!(pending <= max_pending as usize);
            }
        }

        for (i, camera) in [Camera::Cam1, Camera::Cam2].into_iter().enumerate() {
            let writes = b.nvs().writes(camera).replay;
            let budget = accepted_range[i].map_or(0, |(lo, hi)| 1 + u64::from(hi - lo) / u64::from(interval));
            prop_assert!(writes <= budget, "{:?}: {} writes, budget {}", camera, writes, budget);
        }
    }
}
