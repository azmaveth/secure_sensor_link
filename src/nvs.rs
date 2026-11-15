//! Simulated non-volatile store (NVS).
//!
//! Everything here survives `restart`; everything outside it does not. All
//! mutation goes through `write_*` methods, which count writes so tests can
//! check the endurance budget.

use std::collections::BTreeMap;

use crate::camera::{Camera, PerCamera};
use crate::command::Config;
use crate::frame::Key;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySlot {
    pub key: Key,
    pub revoked: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CameraRecord {
    keys: BTreeMap<u8, KeySlot>,
    /// Highest key id used by an accepted frame. Lower ids are retired.
    current_key: u8,
    /// After a restart, frames with `seq <= replay_floor` are rejected.
    /// Wider than `u32` because `seq + persist_interval` can exceed it.
    replay_floor: Option<u64>,
}

/// Write counters, for checking the endurance budget.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriteCounts {
    pub config: u64,
    pub keys: u64,
    pub replay: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Nvs {
    config: Option<Config>,
    cameras: PerCamera<CameraRecord>,
    writes: PerCamera<WriteCounts>,
}

impl Nvs {
    pub fn config(&self) -> Option<Config> {
        self.config
    }

    pub fn key(&self, camera: Camera, key_id: u8) -> Option<&KeySlot> {
        self.cameras[camera].keys.get(&key_id)
    }

    /// Provisioned keys, sorted by id.
    pub fn keys(&self, camera: Camera) -> impl Iterator<Item = (u8, &KeySlot)> {
        self.cameras[camera].keys.iter().map(|(&id, slot)| (id, slot))
    }

    pub fn current_key(&self, camera: Camera) -> u8 {
        self.cameras[camera].current_key
    }

    pub fn replay_floor(&self, camera: Camera) -> Option<u64> {
        self.cameras[camera].replay_floor
    }

    pub fn writes(&self, camera: Camera) -> WriteCounts {
        self.writes[camera]
    }

    pub fn write_init(&mut self, config: Config, keys: &PerCamera<Key>) {
        self.config = Some(config);
        for camera in Camera::ALL {
            self.cameras[camera].keys.insert(0, KeySlot { key: keys[camera], revoked: false });
            self.writes[camera].config += 1;
        }
    }

    pub fn write_key(&mut self, camera: Camera, key_id: u8, key: Key) {
        self.cameras[camera].keys.insert(key_id, KeySlot { key, revoked: false });
        self.writes[camera].keys += 1;
    }

    pub fn write_revocation(&mut self, camera: Camera, key_id: u8) {
        if let Some(slot) = self.cameras[camera].keys.get_mut(&key_id) {
            slot.revoked = true;
            self.writes[camera].keys += 1;
        }
    }

    pub fn write_current_key(&mut self, camera: Camera, key_id: u8) {
        self.cameras[camera].current_key = key_id;
        self.writes[camera].keys += 1;
    }

    pub fn write_replay_floor(&mut self, camera: Camera, floor: u64) {
        self.cameras[camera].replay_floor = Some(floor);
        self.writes[camera].replay += 1;
    }
}
