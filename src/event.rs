//! Diagnostic events for operators, written as JSON lines to stderr.
//!
//! Stdout carries exactly one response per command, so diagnostics never go
//! there. The receiver queues events while handling a command, and
//! [`crate::run`] writes them out afterwards.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// An authentic frame was rejected because its tree is over a size limit.
    /// `nodes` and `depth` are the tree's full size, not where decoding
    /// stopped.
    TreeRejected {
        camera: &'static str,
        key_id: u8,
        seq: u32,
        nodes: usize,
        depth: usize,
        limit_nodes: usize,
        limit_depth: usize,
    },
    /// An accepted tree has more nodes, or more depth, than any earlier tree
    /// from the same camera since the receiver booted. `max_nodes_seen` and
    /// `max_depth_seen` are the camera's maxima after this tree; they may
    /// come from different frames.
    TreeSizeRecord {
        camera: &'static str,
        key_id: u8,
        seq: u32,
        nodes: usize,
        depth: usize,
        max_nodes_seen: usize,
        max_depth_seen: usize,
    },
}

impl Event {
    /// One line of JSON, without the newline.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| r#"{"event":"unencodable"}"#.to_owned())
    }
}
