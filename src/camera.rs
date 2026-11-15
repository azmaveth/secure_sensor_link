//! Camera identities and a fixed-size per-camera container.

use std::fmt;
use std::ops::{Index, IndexMut};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Camera {
    Cam1,
    Cam2,
}

impl Camera {
    pub const ALL: [Camera; 2] = [Camera::Cam1, Camera::Cam2];

    /// Decodes the `camera` byte of a frame.
    pub fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Camera::Cam1),
            0x02 => Some(Camera::Cam2),
            _ => None,
        }
    }

    /// Decodes a camera name as used in commands (`"cam1"`, `"cam2"`).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "cam1" => Some(Camera::Cam1),
            "cam2" => Some(Camera::Cam2),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Camera::Cam1 => "cam1",
            Camera::Cam2 => "cam2",
        }
    }

    fn index(self) -> usize {
        match self {
            Camera::Cam1 => 0,
            Camera::Cam2 => 1,
        }
    }
}

impl fmt::Display for Camera {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One value per camera, indexed by [`Camera`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PerCamera<T>([T; 2]);

impl<T> PerCamera<T> {
    pub fn new(cam1: T, cam2: T) -> Self {
        PerCamera([cam1, cam2])
    }
}

impl<T> Index<Camera> for PerCamera<T> {
    type Output = T;
    fn index(&self, camera: Camera) -> &T {
        &self.0[camera.index()]
    }
}

impl<T> IndexMut<Camera> for PerCamera<T> {
    fn index_mut(&mut self, camera: Camera) -> &mut T {
        &mut self.0[camera.index()]
    }
}
