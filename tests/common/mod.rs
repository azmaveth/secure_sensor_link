//! Shared helpers for integration tests: building signed frames and driving
//! a receiver.

#![allow(dead_code)]

use secure_sensor_link::frame::{Key, compute_tag};
use secure_sensor_link::receiver::Receiver;
use serde_json::{Value, json};

/// A key whose bytes count up from `start`, as in the spec's examples.
pub fn key(start: u8) -> Key {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

pub fn cam1_key() -> Key {
    key(0x00)
}

pub fn cam2_key() -> Key {
    key(0x20)
}

/// A tree for building payloads.
#[derive(Debug, Clone)]
pub enum T {
    Nil,
    Node(i32, Box<T>, Box<T>),
}

impl T {
    pub fn leaf(v: i32) -> T {
        T::Node(v, Box::new(T::Nil), Box::new(T::Nil))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            T::Nil => out.push(0),
            T::Node(v, l, r) => {
                out.push(1);
                out.extend_from_slice(&v.to_be_bytes());
                l.encode_into(out);
                r.encode_into(out);
            }
        }
    }

    /// Reference level-order rendering, written independently of the crate.
    pub fn level_order(&self) -> Vec<Option<i32>> {
        let mut out = Vec::new();
        let mut queue = std::collections::VecDeque::from([self]);
        while let Some(t) = queue.pop_front() {
            match t {
                T::Nil => out.push(None),
                T::Node(v, l, r) => {
                    out.push(Some(*v));
                    queue.push_back(l);
                    queue.push_back(r);
                }
            }
        }
        while out.last() == Some(&None) {
            out.pop();
        }
        out
    }
}

/// A frame under construction. Defaults: version 1, empty tree, signed with
/// the camera's init key.
#[derive(Debug, Clone)]
pub struct F {
    pub version: u8,
    pub camera: u8,
    pub key_id: u8,
    pub seq: u32,
    pub timestamp: i64,
    pub payload: Vec<u8>,
    pub key: Key,
}

pub fn frame(camera: u8, seq: u32, timestamp: i64) -> F {
    F {
        version: 1,
        camera,
        key_id: 0,
        seq,
        timestamp,
        payload: vec![0],
        key: if camera == 2 { cam2_key() } else { cam1_key() },
    }
}

impl F {
    /// Switches to a version 2 frame signed with `key` under `key_id`.
    pub fn v2(mut self, key_id: u8, key: Key) -> F {
        self.version = 2;
        self.key_id = key_id;
        self.key = key;
        self
    }

    pub fn payload(mut self, payload: Vec<u8>) -> F {
        self.payload = payload;
        self
    }

    pub fn tree(self, tree: &T) -> F {
        self.payload(tree.encode())
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut out = vec![self.version, self.camera];
        if self.version == 2 {
            out.push(self.key_id);
        }
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        let tag = compute_tag(&self.key, &out);
        out.extend_from_slice(&tag);
        out
    }

    pub fn hex(&self) -> String {
        hex::encode(self.bytes())
    }
}

pub fn init_command(overrides: Value) -> String {
    let mut params = json!({
        "period_ms": 50,
        "max_jitter_ms": 5,
        "pair_window_ms": 20,
        "max_pending": 4,
        "keys": { "cam1": hex::encode(cam1_key()), "cam2": hex::encode(cam2_key()) },
    });
    if let (Some(p), Value::Object(o)) = (params.as_object_mut(), overrides) {
        p.extend(o);
    }
    json!({ "command": "init", "parameters": params }).to_string()
}

pub fn receive_command(hex_frame: &str) -> String {
    json!({ "command": "receive", "parameters": { "frame": hex_frame } }).to_string()
}

/// A receiver plus helpers that parse and check responses.
pub struct Rx {
    pub receiver: Receiver,
}

impl Rx {
    /// Initialized with the spec's example settings, adjusted by `overrides`.
    pub fn new(overrides: Value) -> Rx {
        let mut rx = Rx { receiver: Receiver::new() };
        rx.ok(&init_command(overrides));
        rx
    }

    pub fn raw(&mut self, line: &str) -> String {
        self.receiver.handle_line(line).to_json()
    }

    pub fn send(&mut self, line: &str) -> Value {
        serde_json::from_str(&self.raw(line)).unwrap()
    }

    /// Sends a command that must succeed and returns its payload.
    #[track_caller]
    pub fn ok(&mut self, line: &str) -> Value {
        let response = self.send(line);
        assert_eq!(response["status"], "ok", "{line}\n-> {response}");
        response["payload"].clone()
    }

    /// Sends a command that must fail and returns its message.
    #[track_caller]
    pub fn err(&mut self, line: &str) -> String {
        let response = self.send(line);
        assert_eq!(response["status"], "error", "{line}\n-> {response}");
        response["payload"]["message"].as_str().unwrap().to_owned()
    }

    #[track_caller]
    pub fn accept(&mut self, f: &F) -> Value {
        self.ok(&receive_command(&f.hex()))
    }

    #[track_caller]
    pub fn reject(&mut self, f: &F) -> String {
        self.err(&receive_command(&f.hex()))
    }

    pub fn state(&mut self) -> Value {
        self.ok(r#"{"command":"get_state","parameters":{}}"#)
    }

    pub fn add_key(&mut self, camera: &str, key_id: u8, key: Key) -> Value {
        self.send(
            &json!({"command":"add_key","parameters":{"camera":camera,"key_id":key_id,"key":hex::encode(key)}})
                .to_string(),
        )
    }

    pub fn revoke_key(&mut self, camera: &str, key_id: u8) -> Value {
        self.send(&json!({"command":"revoke_key","parameters":{"camera":camera,"key_id":key_id}}).to_string())
    }

    pub fn restart(&mut self) -> Value {
        self.ok(r#"{"command":"restart","parameters":{}}"#)
    }
}
