//! Arbitrary bytes as a frame, and as the hex text of one. Parsing must not
//! panic, and a frame it accepts must have exactly the layout the spec gives.

#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_sensor_link::frame::{self, KEY_LEN, MAX_FRAME_LEN, TAG_LEN};

fn check(bytes: &[u8]) {
    let Ok(parsed) = frame::parse(bytes) else { return };
    let header = match parsed.version {
        1 => 16,
        2 => 17,
        other => panic!("accepted version {other}"),
    };
    assert_eq!(bytes.len(), header + parsed.payload.len() + TAG_LEN);
    assert!(bytes.len() <= MAX_FRAME_LEN);
    assert!(parsed.timestamp >= 0);
    assert!(parsed.version == 2 || parsed.key_id == 0);
    assert_eq!(parsed.tag(), &bytes[bytes.len() - TAG_LEN..]);
    // Verifying must not panic whatever the key; the result is not checked.
    let _ = parsed.verify(&[0x5a; KEY_LEN]);
}

fuzz_target!(|data: &[u8]| {
    check(data);
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(bytes) = frame::decode_hex(text)
    {
        assert_eq!(bytes.len() * 2, text.len());
        check(&bytes);
    }
});
