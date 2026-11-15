//! Binary frame layout (versions 1 and 2) and tag verification.
//!
//! Parsing here is purely structural: it never looks at receiver state or
//! keys, and it never interprets the payload. Authentication, replay and
//! payload checks happen in [`crate::receiver`].

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::camera::Camera;

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 32;
const V1_HEADER_LEN: usize = 16;
const V2_HEADER_LEN: usize = 17;

/// The longest frame any version can produce: a version 2 header, the
/// largest payload a `u16` length allows, and the tag.
pub const MAX_FRAME_LEN: usize = V2_HEADER_LEN + u16::MAX as usize + TAG_LEN;

pub type Key = [u8; KEY_LEN];

/// A structurally valid frame, borrowing from the decoded bytes.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    pub version: u8,
    pub camera: Camera,
    /// Version 1 frames are always authenticated with key 0.
    pub key_id: u8,
    pub seq: u32,
    pub timestamp: i64,
    pub payload: &'a [u8],
    /// Bytes `[0, header + payload_len)`, which the tag covers.
    authenticated: &'a [u8],
    tag: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    TooLong { hex_digits: usize },
    InvalidHex,
    Empty,
    UnsupportedVersion(u8),
    TooShort { version: u8, min: usize, actual: usize },
    UnknownCamera(u8),
    LengthMismatch { payload_len: u16, expected: usize, actual: usize },
    NegativeTimestamp(i64),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("malformed frame: ")?;
        match self {
            FrameError::TooLong { hex_digits } => {
                write!(f, "{hex_digits} hex digits is longer than any valid frame ({} bytes)", MAX_FRAME_LEN)
            }
            FrameError::InvalidHex => f.write_str("not valid hex"),
            FrameError::Empty => f.write_str("frame is empty"),
            FrameError::UnsupportedVersion(v) => write!(f, "unsupported version {v}"),
            FrameError::TooShort { version, min, actual } => {
                write!(f, "a version {version} frame is at least {min} bytes, got {actual} bytes")
            }
            FrameError::UnknownCamera(c) => write!(f, "unknown camera 0x{c:02x}"),
            FrameError::LengthMismatch { payload_len, expected, actual } => {
                write!(f, "payload_len {payload_len} implies a {expected}-byte frame, got {actual} bytes")
            }
            FrameError::NegativeTimestamp(t) => write!(f, "negative timestamp {t}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Decodes the hex text of a frame (either case). Text longer than any valid
/// frame is rejected before anything is allocated for it.
pub fn decode_hex(text: &str) -> Result<Vec<u8>, FrameError> {
    if text.len() > 2 * MAX_FRAME_LEN {
        return Err(FrameError::TooLong { hex_digits: text.len() });
    }
    hex::decode(text).map_err(|_| FrameError::InvalidHex)
}

/// Splits raw frame bytes into fields and checks everything that can be
/// checked without a key.
pub fn parse(bytes: &[u8]) -> Result<Frame<'_>, FrameError> {
    let version = *bytes.first().ok_or(FrameError::Empty)?;
    let header_len = match version {
        1 => V1_HEADER_LEN,
        2 => V2_HEADER_LEN,
        other => return Err(FrameError::UnsupportedVersion(other)),
    };
    let min = header_len + TAG_LEN;
    if bytes.len() < min {
        return Err(FrameError::TooShort { version, min, actual: bytes.len() });
    }

    // From here on every fixed-offset read is inside the header, which the
    // length check above guarantees is present.
    let camera_byte = bytes[1];
    let camera = Camera::from_wire(camera_byte).ok_or(FrameError::UnknownCamera(camera_byte))?;
    let (key_id, rest) = match version {
        1 => (0, 2),
        _ => (bytes[2], 3),
    };
    let seq = u32::from_be_bytes(array(bytes, rest));
    let timestamp = i64::from_be_bytes(array(bytes, rest + 4));
    let payload_len = u16::from_be_bytes(array(bytes, rest + 12));

    let expected = header_len + usize::from(payload_len) + TAG_LEN;
    if bytes.len() != expected {
        return Err(FrameError::LengthMismatch { payload_len, expected, actual: bytes.len() });
    }
    if timestamp < 0 {
        return Err(FrameError::NegativeTimestamp(timestamp));
    }

    let (authenticated, tag) = bytes.split_at(header_len + usize::from(payload_len));
    Ok(Frame {
        version,
        camera,
        key_id,
        seq,
        timestamp,
        payload: &authenticated[header_len..],
        authenticated,
        tag,
    })
}

impl Frame<'_> {
    /// Checks the tag against `key`. The comparison is constant-time.
    pub fn verify(&self, key: &Key) -> bool {
        let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(key) else {
            return false;
        };
        mac.update(self.authenticated);
        mac.verify_slice(self.tag).is_ok()
    }
}

/// HMAC-SHA256 of `data` under `key`. Used to build frames in tests and tools.
pub fn compute_tag(key: &Key, data: &[u8]) -> [u8; TAG_LEN] {
    let mut tag = [0u8; TAG_LEN];
    if let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(key) {
        mac.update(data);
        tag.copy_from_slice(&mac.finalize().into_bytes());
    }
    tag
}

/// Copies `N` bytes starting at `at`. Callers guarantee the range is in bounds.
fn array<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[at..at + N]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: Key = [7u8; KEY_LEN];

    fn v1(seq: u32, ts: i64, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![1, 1];
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(&ts.to_be_bytes());
        f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        f.extend_from_slice(payload);
        let tag = compute_tag(&KEY, &f);
        f.extend_from_slice(&tag);
        f
    }

    #[test]
    fn parses_and_verifies_v1() {
        let bytes = v1(9, 1234, &[0]);
        let frame = parse(&bytes).unwrap();
        assert_eq!((frame.camera, frame.key_id, frame.seq, frame.timestamp), (Camera::Cam1, 0, 9, 1234));
        assert_eq!(frame.payload, &[0]);
        assert!(frame.verify(&KEY));
        assert!(!frame.verify(&[8u8; KEY_LEN]));
    }

    #[test]
    fn any_flipped_bit_fails_verification() {
        let bytes = v1(1, 1, &[1, 0, 0, 0, 5, 0, 0]);
        for i in 0..bytes.len() {
            let mut copy = bytes.clone();
            copy[i] ^= 0x01;
            if let Ok(frame) = parse(&copy) {
                assert!(!frame.verify(&KEY), "flip at byte {i} still verified");
            }
        }
    }

    #[test]
    fn rejects_structural_errors() {
        assert_eq!(parse(&[]).unwrap_err(), FrameError::Empty);
        assert_eq!(parse(&[3; 60]).unwrap_err(), FrameError::UnsupportedVersion(3));
        assert!(matches!(parse(&[1; 47]).unwrap_err(), FrameError::TooShort { min: 48, .. }));
        assert!(matches!(parse(&[2; 48]).unwrap_err(), FrameError::TooShort { min: 49, .. }));

        let mut bad_cam = v1(1, 1, &[0]);
        bad_cam[1] = 3;
        assert_eq!(parse(&bad_cam).unwrap_err(), FrameError::UnknownCamera(3));

        let mut long = v1(1, 1, &[0]);
        long.push(0);
        assert!(matches!(
            parse(&long).unwrap_err(),
            FrameError::LengthMismatch { expected: 49, actual: 50, .. }
        ));

        assert_eq!(parse(&v1(1, -1, &[0])).unwrap_err(), FrameError::NegativeTimestamp(-1));
    }

    #[test]
    fn length_mismatch_message_matches_spec() {
        let mut bytes = vec![1u8, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xff];
        bytes.resize(55, 0);
        assert_eq!(
            parse(&bytes).unwrap_err().to_string(),
            "malformed frame: payload_len 65535 implies a 65583-byte frame, got 55 bytes"
        );
    }

    #[test]
    fn hex_is_case_insensitive_and_bounded() {
        assert_eq!(decode_hex("0aFf").unwrap(), vec![0x0a, 0xff]);
        assert_eq!(decode_hex("0g").unwrap_err(), FrameError::InvalidHex);
        assert_eq!(decode_hex("abc").unwrap_err(), FrameError::InvalidHex);
        let huge = "00".repeat(MAX_FRAME_LEN + 1);
        assert!(matches!(decode_hex(&huge).unwrap_err(), FrameError::TooLong { .. }));
    }
}
