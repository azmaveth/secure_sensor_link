//! Diagnostic events for operators, written as JSON lines to stderr.
//!
//! Stdout carries exactly one response per command, so diagnostics never go
//! there. The receiver queues events while handling a command, and
//! [`crate::run`] writes out afterwards those the diagnostics profile
//! allows ([`crate::diagnostics`]); by default that is none of them.

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
    /// A key was revoked. From now on its frames are rejected, and its
    /// queued frames were dropped, but what its earlier frames did is not
    /// undone. The fields after `discarded` report that, so an operator can
    /// judge whether the camera's state can still be trusted.
    KeyRevoked {
        camera: &'static str,
        key_id: u8,
        /// Queued frames from this key that were dropped without being emitted.
        discarded: usize,
        /// The seq a frame from this camera must exceed, if a frame from the
        /// revoked key is what set it; otherwise `null`. A value near
        /// 4294967295 means the camera can no longer be accepted.
        replay_bar: Option<u64>,
        /// A frame from this key set the camera's timeline since the receiver
        /// booted, so later timestamps are corrected relative to it until the
        /// next restart.
        set_timeline: bool,
        /// Unrevoked keys with lower ids that stay retired because this is
        /// the highest key the camera has used. Empty otherwise.
        retired_keys: Vec<u8>,
    },
    /// Key id 255, the highest, was provisioned for a camera (`in_use` is
    /// false) or a camera has moved to it (`in_use` is true). Cameras only
    /// move forward through their keys, so once 255 is in use the camera can
    /// never be re-keyed, and revoking it then disables the camera for good.
    FinalKeyId { camera: &'static str, in_use: bool },
    /// An accepted frame's corrected timestamp is above 9223372036854775807,
    /// the largest signed 64-bit value, for the first time for that camera
    /// since the receiver booted. Arithmetic stays exact and the value still
    /// fits an unsigned 64-bit integer, but a consumer that parses
    /// timestamps as signed 64-bit will not cope. No real clock is near that
    /// value, so it also means the camera's timeline follows a bad timestamp.
    TimestampBeyondI64 { camera: &'static str, key_id: u8, seq: u32, timestamp: i128 },
}

impl Event {
    /// Whether the event bears on trusting a camera's state, as opposed to
    /// describing ordinary traffic. The `security` diagnostics profile
    /// writes only these.
    pub fn is_security(&self) -> bool {
        match self {
            Event::KeyRevoked { .. } | Event::FinalKeyId { .. } | Event::TimestampBeyondI64 { .. } => true,
            Event::TreeRejected { .. } | Event::TreeSizeRecord { .. } => false,
        }
    }

    /// One line of JSON, without the newline.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| r#"{"event":"unencodable"}"#.to_owned())
    }
}
