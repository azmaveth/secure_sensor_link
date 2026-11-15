//! Response envelope and payload shapes.

use serde::Serialize;

use crate::sync::SyncRecord;

#[derive(Debug, Serialize)]
#[serde(tag = "status", content = "payload", rename_all = "lowercase")]
pub enum Response {
    Ok(Payload),
    Error(ErrorPayload),
}

#[derive(Debug, Serialize)]
pub struct ErrorPayload {
    pub message: String,
}

impl Response {
    pub fn error(message: impl Into<String>) -> Self {
        Response::Error(ErrorPayload { message: message.into() })
    }

    /// One line of JSON, without the newline.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"status":"error","payload":{"message":"internal error: response could not be encoded"}}"#
                .to_owned()
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Payload {
    State(StateView),
    Receive(ReceiveView),
}

#[derive(Debug, Serialize)]
pub struct StateView {
    pub cameras: CamerasView,
}

#[derive(Debug, Serialize)]
pub struct CamerasView {
    pub cam1: CameraView,
    pub cam2: CameraView,
}

#[derive(Debug, Serialize)]
pub struct CameraView {
    pub last_seq: Option<u32>,
    pub last_timestamp: Option<i128>,
    pub pending: Vec<u32>,
    pub keys: Vec<KeyView>,
}

#[derive(Debug, Serialize)]
pub struct KeyView {
    pub key_id: u8,
    pub status: KeyStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Active,
    Retired,
    Revoked,
}

#[derive(Debug, Serialize)]
pub struct ReceiveView {
    pub frame: FrameView,
    pub synced: Vec<SyncRecord>,
}

#[derive(Debug, Serialize)]
pub struct FrameView {
    pub camera: &'static str,
    pub key_id: u8,
    pub seq: u32,
    pub timestamp: i128,
    pub corrected: bool,
    pub tree: Vec<Option<i32>>,
}
