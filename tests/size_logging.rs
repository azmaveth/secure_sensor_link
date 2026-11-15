//! Tree-size diagnostics: trees rejected for breaking a size limit, and new
//! per-camera size records among accepted trees. These go to the log
//! stream, never to stdout.

mod common;

use std::io;

use common::*;
use secure_sensor_link::event::Event;
use serde_json::{Value, json};

fn rejected(camera: &'static str, seq: u32, nodes: usize, depth: usize) -> Event {
    Event::TreeRejected { camera, key_id: 0, seq, nodes, depth, limit_nodes: 1024, limit_depth: 64 }
}

fn record(camera: &'static str, seq: u32, shape: (usize, usize), max_seen: (usize, usize)) -> Event {
    Event::TreeSizeRecord {
        camera,
        key_id: 0,
        seq,
        nodes: shape.0,
        depth: shape.1,
        max_nodes_seen: max_seen.0,
        max_depth_seen: max_seen.1,
    }
}

fn accept_tree(rx: &mut Rx, camera: u8, seq: u32, tree: &T) -> Vec<Event> {
    rx.accept(&frame(camera, seq, 50 * i64::from(seq)).tree(tree));
    rx.receiver.take_events()
}

#[test]
fn too_deep_tree_is_logged_with_its_full_size() {
    let mut rx = Rx::new(json!({}));
    rx.reject(&frame(1, 5, 0).tree(&T::spine(70)));
    assert_eq!(rx.receiver.take_events(), vec![rejected("cam1", 5, 70, 70)]);
    assert!(rx.receiver.take_events().is_empty(), "each event is handed out once");
}

#[test]
fn tree_with_too_many_nodes_is_logged_with_its_full_size() {
    let mut rx = Rx::new(json!({}));
    let message = rx.reject(&frame(2, 9, 0).tree(&T::balanced(1100)));
    assert!(message.contains("1100 nodes, depth 11"), "{message}");
    assert_eq!(rx.receiver.take_events(), vec![rejected("cam2", 9, 1100, 11)]);
}

#[test]
fn rejected_v2_frame_reports_its_key_id() {
    let mut rx = Rx::new(json!({}));
    rx.add_key("cam1", 4, key(0x40));
    rx.reject(&frame(1, 1, 0).v2(4, key(0x40)).tree(&T::spine(65)));
    let events = rx.receiver.take_events();
    assert!(matches!(events.as_slice(), [Event::TreeRejected { key_id: 4, .. }]), "{events:?}");
}

#[test]
fn other_rejections_are_not_logged() {
    let mut rx = Rx::new(json!({}));
    // Malformed, but not for size.
    rx.reject(&frame(1, 1, 0).payload(vec![2]));
    // Oversized, but forged: authentication fails before the tree is read.
    let mut forged = frame(1, 2, 50).tree(&T::spine(70));
    forged.key = key(0xee);
    rx.reject(&forged);
    // Oversized, but replayed: the replay check comes first.
    rx.accept(&frame(1, 3, 100));
    rx.receiver.take_events();
    rx.reject(&frame(1, 3, 100).tree(&T::spine(70)));
    assert_eq!(rx.receiver.take_events(), vec![]);
}

#[test]
fn each_new_size_record_is_logged_once_per_camera() {
    let mut rx = Rx::new(json!({}));
    assert_eq!(accept_tree(&mut rx, 1, 1, &T::Nil), vec![], "the empty tree sets no record");
    assert_eq!(accept_tree(&mut rx, 1, 2, &T::leaf(0)), vec![record("cam1", 2, (1, 1), (1, 1))]);
    assert_eq!(accept_tree(&mut rx, 1, 3, &T::leaf(0)), vec![], "ties are not records");
    assert_eq!(accept_tree(&mut rx, 1, 4, &T::spine(3)), vec![record("cam1", 4, (3, 3), (3, 3))]);
    assert_eq!(accept_tree(&mut rx, 1, 5, &T::balanced(3)), vec![], "3 nodes, depth 2: no record");
    assert_eq!(accept_tree(&mut rx, 1, 6, &T::balanced(7)), vec![record("cam1", 6, (7, 3), (7, 3))]);
    // Deeper but smaller: a depth record, with the node maximum unchanged.
    assert_eq!(accept_tree(&mut rx, 1, 7, &T::spine(5)), vec![record("cam1", 7, (5, 5), (7, 5))]);
    // Each camera keeps its own records.
    assert_eq!(accept_tree(&mut rx, 2, 1, &T::leaf(0)), vec![record("cam2", 1, (1, 1), (1, 1))]);
}

#[test]
fn a_replayed_oversized_frame_is_logged_once() {
    let mut rx = Rx::new(json!({}));
    let oversized = frame(1, 5, 0).tree(&T::spine(70));
    assert!(rx.reject(&oversized).contains("tree is too large"));
    for _ in 0..100 {
        assert_eq!(rx.reject(&oversized), "stale or replayed frame: cam1 seq 5");
    }
    assert_eq!(rx.receiver.take_events(), vec![rejected("cam1", 5, 70, 70)]);
}

#[test]
fn records_start_over_after_a_restart() {
    let mut rx = Rx::new(json!({}));
    assert_eq!(accept_tree(&mut rx, 1, 1, &T::leaf(0)).len(), 1);
    rx.restart();
    assert_eq!(accept_tree(&mut rx, 1, 500, &T::leaf(0)), vec![record("cam1", 500, (1, 1), (1, 1))]);
}

fn lines(bytes: Vec<u8>) -> Vec<Value> {
    String::from_utf8(bytes).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn session() -> Vec<u8> {
    [
        init_command(json!({})),
        receive_command(&frame(1, 1, 0).tree(&T::spine(3)).hex()),
        receive_command(&frame(1, 2, 50).tree(&T::spine(70)).hex()),
        r#"{"command":"get_state","parameters":{}}"#.to_owned(),
    ]
    .join("\n")
    .into_bytes()
}

#[test]
fn run_writes_events_to_the_log_and_only_responses_to_output() {
    let (mut out, mut log) = (Vec::new(), Vec::new());
    secure_sensor_link::run(session().as_slice(), &mut out, &mut log).unwrap();

    let responses = lines(out);
    assert_eq!(responses.len(), 4);
    assert!(responses.iter().all(|r| r.get("status").is_some()));
    assert_eq!(
        lines(log),
        vec![
            json!({"event":"tree_size_record","camera":"cam1","key_id":0,"seq":1,
                   "nodes":3,"depth":3,"max_nodes_seen":3,"max_depth_seen":3}),
            json!({"event":"tree_rejected","camera":"cam1","key_id":0,"seq":2,
                   "nodes":70,"depth":70,"limit_nodes":1024,"limit_depth":64}),
        ]
    );
}

/// A log stream that always fails, like a closed stderr.
struct BrokenLog;

impl io::Write for BrokenLog {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

#[test]
fn a_failing_log_does_not_stop_the_receiver() {
    let mut out = Vec::new();
    secure_sensor_link::run(session().as_slice(), &mut out, BrokenLog).unwrap();
    assert_eq!(lines(out).len(), 4);
}
