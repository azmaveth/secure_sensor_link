//! Key-management diagnostics: what a revoked key leaves behind, and the
//! last key id. These go to the log stream, never to stdout.

mod common;

use common::*;
use secure_sensor_link::diagnostics::Diagnostics;
use secure_sensor_link::event::Event;
use serde_json::{Value, json};

fn revoked(
    camera: &'static str,
    key_id: u8,
    discarded: usize,
    replay_bar: Option<u64>,
    set_timeline: bool,
    retired_keys: &[u8],
) -> Event {
    Event::KeyRevoked {
        camera,
        key_id,
        discarded,
        replay_bar,
        set_timeline,
        retired_keys: retired_keys.to_vec(),
    }
}

/// Revokes a key and returns the events that produced.
fn revoke(rx: &mut Rx, camera: &str, key_id: u8) -> Vec<Event> {
    rx.receiver.take_events();
    assert_eq!(rx.revoke_key(camera, key_id)["status"], "ok");
    rx.receiver.take_events()
}

#[test]
fn revoking_an_unused_key_reports_nothing_left_behind() {
    let mut rx = Rx::new(json!({}));
    assert_eq!(revoke(&mut rx, "cam2", 0), vec![revoked("cam2", 0, 0, None, false, &[])]);
    assert_eq!(revoke(&mut rx, "cam2", 0), vec![], "revoking again changes nothing and logs nothing");
    assert_eq!(rx.revoke_key("cam2", 9)["status"], "error");
    assert_eq!(rx.receiver.take_events(), vec![], "a failed revocation logs nothing");
}

#[test]
fn revocation_reports_the_replay_bar_and_timeline_the_key_set() {
    let mut rx = Rx::new(json!({}));
    rx.accept(&frame(1, 1, 1000));
    rx.accept(&frame(1, 2, 1050));
    // Both frames are queued, the last accepted seq is 2, and key 0 set the timeline.
    assert_eq!(revoke(&mut rx, "cam1", 0), vec![revoked("cam1", 0, 2, Some(2), true, &[])]);
}

#[test]
fn a_sequence_number_burned_with_a_revoked_key_is_reported() {
    let mut rx = Rx::new(json!({}));
    rx.add_key("cam1", 1, key(0x40));
    rx.accept(&frame(1, 1, 1000).v2(1, key(0x40)));
    // Whoever holds key 1 uses up the whole sequence space.
    rx.accept(&frame(1, u32::MAX, 1050).v2(1, key(0x40)));
    assert_eq!(
        revoke(&mut rx, "cam1", 1),
        vec![revoked("cam1", 1, 2, Some(u64::from(u32::MAX)), true, &[0])]
    );

    // Revocation can't give the sequence space back: a new key doesn't help.
    rx.add_key("cam1", 2, key(0x60));
    assert_eq!(rx.reject(&frame(1, 2, 1100).v2(2, key(0x60))), "stale or replayed frame: cam1 seq 2");
}

#[test]
fn after_a_restart_the_persisted_floor_is_attributed_to_its_key() {
    let mut rx = Rx::new(json!({}));
    rx.add_key("cam1", 1, key(0x40));
    rx.accept(&frame(1, 7, 1000));
    rx.restart();
    // Nothing accepted since boot: the bar is the floor written for seq 7,
    // which key 0 authenticated. The timeline started over at the restart.
    rx.receiver.take_events();
    assert_eq!(rx.revoke_key("cam1", 1)["status"], "ok");
    assert_eq!(rx.receiver.take_events(), vec![revoked("cam1", 1, 0, None, false, &[])]);
    assert_eq!(revoke(&mut rx, "cam1", 0), vec![revoked("cam1", 0, 0, Some(107), false, &[])]);
}

#[test]
fn the_bar_and_timeline_are_not_attributed_to_a_key_that_did_not_set_them() {
    let mut rx = Rx::new(json!({}));
    rx.add_key("cam1", 1, key(0x40));
    rx.accept(&frame(1, 1, 1000));
    // Key 1's only frame has a bad timestamp, so it is corrected: it moves
    // the replay bar but takes its time from key 0's timeline.
    let p = rx.accept(&frame(1, 2, 9999).v2(1, key(0x40)));
    assert_eq!(p["frame"]["corrected"], true);
    // Key 0 is already retired; revoking it now drops its queued frame and
    // reports that it set the timeline, but not the bar, and retired nothing.
    assert_eq!(revoke(&mut rx, "cam1", 0), vec![revoked("cam1", 0, 1, None, true, &[])]);
    // Key 1 was the highest in use. Key 0 is revoked, so it isn't listed as retired.
    assert_eq!(revoke(&mut rx, "cam1", 1), vec![revoked("cam1", 1, 1, Some(2), false, &[])]);
}

#[test]
fn the_last_key_id_is_flagged_when_provisioned_and_when_used() {
    let mut rx = Rx::new(json!({}));
    rx.receiver.take_events();
    assert_eq!(rx.add_key("cam1", 254, key(0x40))["status"], "ok");
    assert_eq!(rx.receiver.take_events(), vec![]);
    assert_eq!(rx.add_key("cam1", 255, key(0x60))["status"], "ok");
    assert_eq!(rx.receiver.take_events(), vec![Event::FinalKeyId { camera: "cam1", in_use: false }]);
    assert_eq!(rx.add_key("cam1", 255, key(0x60))["status"], "ok");
    assert_eq!(rx.receiver.take_events(), vec![], "re-sending the same key is a no-op");

    rx.accept(&frame(1, 1, 0).v2(255, key(0x60)));
    assert_eq!(rx.receiver.take_events(), vec![Event::FinalKeyId { camera: "cam1", in_use: true }]);
    rx.accept(&frame(1, 2, 50).v2(255, key(0x60)));
    assert_eq!(rx.receiver.take_events(), vec![], "flagged once, when the camera moves to it");

    // The camera can't be re-keyed from here.
    assert_eq!(revoke(&mut rx, "cam1", 255), vec![revoked("cam1", 255, 2, Some(2), true, &[0, 254])]);
    assert_eq!(rx.add_key("cam1", 100, key(0x70))["status"], "error");
}

#[test]
fn key_events_are_written_to_the_log_as_json_lines() {
    let input = [
        init_command(json!({})),
        receive_command(&frame(1, 1, 1000).hex()),
        json!({"command":"revoke_key","parameters":{"camera":"cam1","key_id":0}}).to_string(),
        json!({"command":"add_key","parameters":{"camera":"cam2","key_id":255,"key":hex::encode(key(0x40))}})
            .to_string(),
    ]
    .join("\n");
    let (mut out, mut log) = (Vec::new(), Vec::new());
    secure_sensor_link::run(input.as_bytes(), &mut out, &mut log, Diagnostics::Security).unwrap();
    let log: Vec<Value> =
        String::from_utf8(log).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(
        log,
        vec![
            json!({"event":"key_revoked","camera":"cam1","key_id":0,"discarded":1,
                   "replay_bar":1,"set_timeline":true,"retired_keys":[]}),
            json!({"event":"final_key_id","camera":"cam2","in_use":false}),
        ]
    );
}
