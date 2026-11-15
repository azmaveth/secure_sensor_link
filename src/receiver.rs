//! The receiver state machine: one method per command.
//!
//! State is split by what survives a restart: [`Nvs`] does, [`Ram`] does not.
//! Every command validates fully before it changes anything, so a command
//! that returns an error leaves the receiver exactly as it was.

use crate::camera::{Camera, PerCamera};
use crate::command::{self, Command, Config};
use crate::frame::{self, Key};
use crate::nvs::Nvs;
use crate::response::{
    CameraView, CamerasView, FrameView, KeyStatus, KeyView, Payload, ReceiveView, Response, StateView,
};
use crate::sync::{Pending, Synchronizer};
use crate::tree;

const NOT_INITIALIZED: &str = "receiver is not initialized: the first command must be init";

/// Volatile state, wiped by a restart.
#[derive(Debug, Default, Clone)]
struct Ram {
    /// Seq and corrected timestamp of the last frame accepted since boot.
    last: PerCamera<Option<Last>>,
    sync: Synchronizer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Last {
    seq: u32,
    timestamp: i128,
}

#[derive(Debug, Default, Clone)]
pub struct Receiver {
    nvs: Nvs,
    ram: Ram,
}

impl Receiver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles one line of input and returns its response.
    pub fn handle_line(&mut self, line: &str) -> Response {
        match command::parse(line).and_then(|command| self.execute(command)) {
            Ok(payload) => Response::Ok(payload),
            Err(message) => Response::error(message),
        }
    }

    pub fn execute(&mut self, command: Command) -> Result<Payload, String> {
        let Some(config) = self.nvs.config() else {
            return match command {
                Command::Init { config, keys } => {
                    self.nvs.write_init(config, &keys);
                    Ok(self.state())
                }
                _ => Err(NOT_INITIALIZED.into()),
            };
        };
        match command {
            Command::Init { .. } => Err("receiver is already initialized".into()),
            Command::Receive { frame } => self.receive(&frame, config),
            Command::GetState => Ok(self.state()),
            Command::AddKey { camera, key_id, key } => self.add_key(camera, key_id, key),
            Command::RevokeKey { camera, key_id } => self.revoke_key(camera, key_id),
            Command::Restart => {
                self.ram = Ram::default();
                Ok(self.state())
            }
        }
    }

    /// The non-volatile store, for inspecting persistence in tests.
    pub fn nvs(&self) -> &Nvs {
        &self.nvs
    }

    fn receive(&mut self, hex_text: &str, config: Config) -> Result<Payload, String> {
        // 1. Structure: hex, version, length, camera, timestamp sign.
        let bytes = frame::decode_hex(hex_text).map_err(|e| e.to_string())?;
        let frame = frame::parse(&bytes).map_err(|e| e.to_string())?;
        let camera = frame.camera;

        // 2. Key: provisioned, not revoked, not retired.
        let key = self.usable_key(camera, frame.key_id)?;

        // 3. Authenticity.
        if !frame.verify(key) {
            return Err(format!("authentication failed for {camera}"));
        }

        // 4. Freshness.
        if self.replay_floor(camera).is_some_and(|floor| u64::from(frame.seq) <= floor) {
            return Err(format!("stale or replayed frame: {camera} seq {}", frame.seq));
        }

        // 5. Payload.
        let tree = tree::decode(frame.payload).map_err(|e| format!("malformed frame: invalid tree: {e}"))?;

        // 6. Timestamp.
        let (timestamp, corrected) =
            correct_timestamp(self.ram.last[camera], frame.seq, frame.timestamp, &config);

        // Accept. Nothing below can fail.
        self.reserve_replay_window(camera, frame.seq, config.persist_interval);
        if frame.key_id > self.nvs.current_key(camera) {
            self.nvs.write_current_key(camera, frame.key_id);
        }
        self.ram.last[camera] = Some(Last { seq: frame.seq, timestamp });
        let synced = self.ram.sync.push(
            camera,
            Pending { seq: frame.seq, timestamp, key_id: frame.key_id },
            config.pair_window_ms,
            config.max_pending,
        );

        Ok(Payload::Receive(ReceiveView {
            frame: FrameView {
                camera: camera.name(),
                key_id: frame.key_id,
                seq: frame.seq,
                timestamp,
                corrected,
                tree: tree.level_order(),
            },
            synced,
        }))
    }

    fn usable_key(&self, camera: Camera, key_id: u8) -> Result<&Key, String> {
        let slot = self
            .nvs
            .key(camera, key_id)
            .ok_or_else(|| format!("{camera} key {key_id} is not provisioned"))?;
        match self.key_status(camera, key_id, slot.revoked) {
            KeyStatus::Active => Ok(&slot.key),
            KeyStatus::Revoked => Err(format!("{camera} key {key_id} is revoked")),
            KeyStatus::Retired => Err(format!("{camera} key {key_id} is retired")),
        }
    }

    fn key_status(&self, camera: Camera, key_id: u8, revoked: bool) -> KeyStatus {
        if revoked {
            KeyStatus::Revoked
        } else if key_id < self.nvs.current_key(camera) {
            KeyStatus::Retired
        } else {
            KeyStatus::Active
        }
    }

    /// A frame's seq must be above this to be fresh. While running it is the
    /// last accepted seq; after a restart, until a frame is accepted, it is
    /// the floor reserved in NVS.
    fn replay_floor(&self, camera: Camera) -> Option<u64> {
        match self.ram.last[camera] {
            Some(last) => Some(u64::from(last.seq)),
            None => self.nvs.replay_floor(camera),
        }
    }

    /// Keeps the NVS replay floor at or above every accepted seq. It is
    /// rewritten only when an accepted seq passes it, and then set
    /// `persist_interval` ahead, so writes happen at seqs more than
    /// `persist_interval` apart and the floor never exceeds the highest
    /// accepted seq by more than `persist_interval`.
    fn reserve_replay_window(&mut self, camera: Camera, seq: u32, persist_interval: u32) {
        let seq = u64::from(seq);
        if self.nvs.replay_floor(camera).is_none_or(|floor| seq > floor) {
            self.nvs.write_replay_floor(camera, seq + u64::from(persist_interval));
        }
    }

    fn add_key(&mut self, camera: Camera, key_id: u8, key: Key) -> Result<Payload, String> {
        match self.nvs.key(camera, key_id) {
            Some(slot) if slot.revoked => {
                return Err(format!("{camera} key {key_id} is revoked and cannot be provisioned again"));
            }
            // Re-sending an identical key is a no-op, so a retried request succeeds.
            Some(slot) if slot.key == key => {}
            Some(_) => {
                return Err(format!("{camera} key {key_id} is already provisioned with a different key"));
            }
            None if key_id < self.nvs.current_key(camera) => {
                return Err(format!(
                    "{camera} key {key_id} is older than the key in use ({}) and would be retired",
                    self.nvs.current_key(camera)
                ));
            }
            None => self.nvs.write_key(camera, key_id, key),
        }
        Ok(self.state())
    }

    fn revoke_key(&mut self, camera: Camera, key_id: u8) -> Result<Payload, String> {
        let slot = self
            .nvs
            .key(camera, key_id)
            .ok_or_else(|| format!("{camera} key {key_id} is not provisioned"))?;
        if !slot.revoked {
            self.nvs.write_revocation(camera, key_id);
            // Frames this key authenticated are no longer trusted.
            self.ram.sync.discard_key(camera, key_id);
        }
        Ok(self.state())
    }

    fn state(&self) -> Payload {
        Payload::State(StateView {
            cameras: CamerasView {
                cam1: self.camera_view(Camera::Cam1),
                cam2: self.camera_view(Camera::Cam2),
            },
        })
    }

    fn camera_view(&self, camera: Camera) -> CameraView {
        let last = self.ram.last[camera];
        CameraView {
            last_seq: last.map(|l| l.seq),
            last_timestamp: last.map(|l| l.timestamp),
            pending: self.ram.sync.pending(camera),
            keys: self
                .nvs
                .keys(camera)
                .map(|(key_id, slot)| KeyView {
                    key_id,
                    status: self.key_status(camera, key_id, slot.revoked),
                })
                .collect(),
        }
    }
}

/// Returns the corrected timestamp and whether it was replaced. Exact: the
/// inputs are at most 64 bits wide (with a gap of at most 2^32 * 60000), so
/// `i128` cannot overflow.
fn correct_timestamp(last: Option<Last>, seq: u32, timestamp: i64, config: &Config) -> (i128, bool) {
    let timestamp = i128::from(timestamp);
    let Some(last) = last else {
        return (timestamp, false);
    };
    let expected = last.timestamp + (i128::from(seq) - i128::from(last.seq)) * i128::from(config.period_ms);
    if (timestamp - expected).abs() > i128::from(config.max_jitter_ms) {
        (expected, true)
    } else {
        (timestamp, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config { period_ms: 50, max_jitter_ms: 5, pair_window_ms: 20, max_pending: 4, persist_interval: 100 }
    }

    #[test]
    fn first_frame_keeps_its_timestamp() {
        assert_eq!(correct_timestamp(None, 7, 123, &config()), (123, false));
    }

    #[test]
    fn jitter_bound_is_inclusive() {
        let last = Some(Last { seq: 1, timestamp: 1000 });
        assert_eq!(correct_timestamp(last, 2, 1055, &config()), (1055, false));
        assert_eq!(correct_timestamp(last, 2, 1045, &config()), (1045, false));
        assert_eq!(correct_timestamp(last, 2, 1056, &config()), (1050, true));
        assert_eq!(correct_timestamp(last, 2, 1044, &config()), (1050, true));
    }

    #[test]
    fn correction_is_exact_beyond_i64() {
        let config = Config { period_ms: 60_000, max_jitter_ms: 0, ..config() };
        let last = Some(Last { seq: 0, timestamp: i128::from(i64::MAX) });
        let (ts, corrected) = correct_timestamp(last, u32::MAX, 0, &config);
        assert!(corrected);
        assert_eq!(ts, i128::from(i64::MAX) + i128::from(u32::MAX) * 60_000);
    }
}
