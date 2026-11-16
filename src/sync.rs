//! Pairing accepted frames from the two cameras into one stream.

use std::collections::VecDeque;

use serde::Serialize;

use crate::camera::{Camera, PerCamera};

/// An accepted frame waiting for a partner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pending {
    pub seq: u32,
    /// Corrected timestamp.
    pub timestamp: i128,
    /// The key that authenticated the frame, so revocation can find it.
    pub key_id: u8,
}

/// One record of the synchronized stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SyncRecord {
    pub timestamp: i128,
    pub cam1: Option<u32>,
    pub cam2: Option<u32>,
}

impl SyncRecord {
    fn unpaired(camera: Camera, frame: Pending) -> Self {
        let seq = Some(frame.seq);
        match camera {
            Camera::Cam1 => SyncRecord { timestamp: frame.timestamp, cam1: seq, cam2: None },
            Camera::Cam2 => SyncRecord { timestamp: frame.timestamp, cam1: None, cam2: seq },
        }
    }
}

/// Per-camera queues. Each holds at most `max_pending` frames between calls.
#[derive(Debug, Default, Clone)]
pub struct Synchronizer {
    queues: PerCamera<VecDeque<Pending>>,
}

impl Synchronizer {
    /// Queues a newly accepted frame and returns the records it releases.
    pub fn push(
        &mut self,
        camera: Camera,
        frame: Pending,
        pair_window_ms: u32,
        max_pending: usize,
    ) -> Vec<SyncRecord> {
        let mut out = Vec::new();
        self.queues[camera].push_back(frame);

        // Step 1: settle the heads of the two queues. Every iteration removes
        // at least one frame, so this ends.
        while let (Some(&a), Some(&b)) =
            (self.queues[Camera::Cam1].front(), self.queues[Camera::Cam2].front())
        {
            if a.timestamp.abs_diff(b.timestamp) <= u128::from(pair_window_ms) {
                self.queues[Camera::Cam1].pop_front();
                self.queues[Camera::Cam2].pop_front();
                out.push(SyncRecord {
                    // Both are non-negative, so `/` is the floor.
                    timestamp: (a.timestamp + b.timestamp) / 2,
                    cam1: Some(a.seq),
                    cam2: Some(b.seq),
                });
            } else {
                let older = if a.timestamp < b.timestamp { Camera::Cam1 } else { Camera::Cam2 };
                if let Some(frame) = self.queues[older].pop_front() {
                    out.push(SyncRecord::unpaired(older, frame));
                }
            }
        }

        // Step 2: bound the queues.
        for camera in Camera::ALL {
            while self.queues[camera].len() > max_pending {
                if let Some(frame) = self.queues[camera].pop_front() {
                    out.push(SyncRecord::unpaired(camera, frame));
                }
            }
        }
        out
    }

    /// Seqs waiting in a camera's queue, oldest first.
    pub fn pending(&self, camera: Camera) -> Vec<u32> {
        self.queues[camera].iter().map(|p| p.seq).collect()
    }

    /// Drops, without emitting, every queued frame from `camera` that was
    /// authenticated with `key_id`, and returns how many there were.
    pub fn discard_key(&mut self, camera: Camera, key_id: u8) -> usize {
        let before = self.queues[camera].len();
        self.queues[camera].retain(|p| p.key_id != key_id);
        before - self.queues[camera].len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(seq: u32, timestamp: i128) -> Pending {
        Pending { seq, timestamp, key_id: 0 }
    }

    #[test]
    fn pairs_within_window_with_floor_average() {
        let mut s = Synchronizer::default();
        assert!(s.push(Camera::Cam1, p(1, 1000), 20, 4).is_empty());
        let out = s.push(Camera::Cam2, p(1, 1005), 20, 4);
        assert_eq!(out, vec![SyncRecord { timestamp: 1002, cam1: Some(1), cam2: Some(1) }]);
    }

    #[test]
    fn window_is_inclusive() {
        let mut s = Synchronizer::default();
        s.push(Camera::Cam1, p(1, 100), 20, 4);
        assert_eq!(s.push(Camera::Cam2, p(1, 120), 20, 4)[0].cam1, Some(1));
    }

    #[test]
    fn older_unmatched_head_is_emitted_alone() {
        let mut s = Synchronizer::default();
        s.push(Camera::Cam1, p(4, 1150), 20, 4);
        let out = s.push(Camera::Cam2, p(3, 1104), 20, 4);
        assert_eq!(out, vec![SyncRecord { timestamp: 1104, cam1: None, cam2: Some(3) }]);
        assert_eq!(s.pending(Camera::Cam1), vec![4]);
    }

    #[test]
    fn overflowing_queue_emits_its_oldest() {
        let mut s = Synchronizer::default();
        for seq in 1..=2 {
            assert!(s.push(Camera::Cam1, p(seq, i128::from(seq) * 50), 20, 2).is_empty());
        }
        let out = s.push(Camera::Cam1, p(3, 150), 20, 2);
        assert_eq!(out, vec![SyncRecord { timestamp: 50, cam1: Some(1), cam2: None }]);
        assert_eq!(s.pending(Camera::Cam1), vec![2, 3]);
    }

    #[test]
    fn discard_key_removes_only_that_key() {
        let mut s = Synchronizer::default();
        s.push(Camera::Cam1, Pending { seq: 1, timestamp: 0, key_id: 0 }, 0, 4);
        s.push(Camera::Cam1, Pending { seq: 2, timestamp: 50, key_id: 1 }, 0, 4);
        assert_eq!(s.discard_key(Camera::Cam1, 0), 1);
        assert_eq!(s.pending(Camera::Cam1), vec![2]);
        assert_eq!(s.discard_key(Camera::Cam1, 0), 0);
    }
}
