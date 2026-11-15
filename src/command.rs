//! Parsing and validating one line of input into a typed [`Command`].
//!
//! Everything about the shape of a command is checked here, so the receiver
//! only ever sees well-typed, in-range parameters.

use serde_json::{Map, Value};

use crate::camera::{Camera, PerCamera};
use crate::frame::{KEY_LEN, Key};

pub const DEFAULT_PERSIST_INTERVAL: u32 = 100;

/// Receiver configuration from `init`. Survives restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub period_ms: u32,
    pub max_jitter_ms: u32,
    pub pair_window_ms: u32,
    pub max_pending: usize,
    pub persist_interval: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Init { config: Config, keys: PerCamera<Key> },
    Receive { frame: String },
    GetState,
    AddKey { camera: Camera, key_id: u8, key: Key },
    RevokeKey { camera: Camera, key_id: u8 },
    Restart,
}

/// Parses one input line. The error is the message for the response.
pub fn parse(line: &str) -> Result<Command, String> {
    let value: Value = serde_json::from_str(line).map_err(|e| format!("invalid JSON: {e}"))?;
    let Value::Object(mut object) = value else {
        return Err("a command must be a JSON object".into());
    };
    let name = match object.remove("command") {
        Some(Value::String(name)) => name,
        Some(_) => return Err("\"command\" must be a string".into()),
        None => return Err("missing \"command\"".into()),
    };
    let empty = Map::new();
    let params = match object.get("parameters") {
        Some(Value::Object(params)) => Params(params),
        None => Params(&empty),
        Some(_) => return Err("\"parameters\" must be a JSON object".into()),
    };

    match name.as_str() {
        "init" => parse_init(params),
        "receive" => Ok(Command::Receive { frame: params.string("frame")?.to_owned() }),
        "get_state" => Ok(Command::GetState),
        "add_key" => Ok(Command::AddKey {
            camera: params.camera("camera")?,
            key_id: params.key_id("key_id")?,
            key: params.key("key")?,
        }),
        "revoke_key" => {
            Ok(Command::RevokeKey { camera: params.camera("camera")?, key_id: params.key_id("key_id")? })
        }
        "restart" => Ok(Command::Restart),
        other => Err(format!("unknown command: {other:?}")),
    }
}

fn parse_init(params: Params<'_>) -> Result<Command, String> {
    let period_ms = params.int("period_ms", 1, 60_000)?;
    let config = Config {
        period_ms,
        max_jitter_ms: params.int("max_jitter_ms", 0, period_ms - 1)?,
        pair_window_ms: params.int("pair_window_ms", 0, period_ms - 1)?,
        max_pending: params.int("max_pending", 1, 1024)? as usize,
        persist_interval: match params.0.get("persist_interval") {
            None => DEFAULT_PERSIST_INTERVAL,
            Some(_) => params.int("persist_interval", 1, u32::MAX)?,
        },
    };

    let keys = match params.0.get("keys") {
        Some(Value::Object(keys)) => keys,
        Some(_) => return Err("parameter \"keys\" must be an object".into()),
        None => return Err("missing parameter \"keys\"".into()),
    };
    if let Some(unknown) = keys.keys().find(|name| Camera::from_name(name).is_none()) {
        return Err(format!("parameter \"keys\" names an unknown camera {unknown:?}"));
    }
    let keys = Params(keys);
    let keys = PerCamera::new(keys.key("cam1")?, keys.key("cam2")?);
    Ok(Command::Init { config, keys })
}

/// Typed accessors over a `parameters` object.
#[derive(Clone, Copy)]
struct Params<'a>(&'a Map<String, Value>);

impl Params<'_> {
    fn get(&self, name: &str) -> Result<&Value, String> {
        self.0.get(name).ok_or_else(|| format!("missing parameter {name:?}"))
    }

    fn int(&self, name: &str, min: u32, max: u32) -> Result<u32, String> {
        let value = self.get(name)?;
        value
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| (min..=max).contains(n))
            .ok_or_else(|| format!("parameter {name:?} must be an integer from {min} to {max}"))
    }

    fn string(&self, name: &str) -> Result<&str, String> {
        self.get(name)?.as_str().ok_or_else(|| format!("parameter {name:?} must be a string"))
    }

    fn camera(&self, name: &str) -> Result<Camera, String> {
        let value = self.string(name)?;
        Camera::from_name(value)
            .ok_or_else(|| format!("parameter {name:?} must be \"cam1\" or \"cam2\", got {value:?}"))
    }

    fn key_id(&self, name: &str) -> Result<u8, String> {
        Ok(self.int(name, 0, u8::MAX.into())? as u8)
    }

    fn key(&self, name: &str) -> Result<Key, String> {
        let invalid = || format!("parameter {name:?} must be a hex-encoded {KEY_LEN}-byte key");
        let text = self.string(name).map_err(|_| invalid())?;
        if text.len() != 2 * KEY_LEN {
            return Err(invalid());
        }
        let mut key = [0u8; KEY_LEN];
        hex::decode_to_slice(text, &mut key).map_err(|_| invalid())?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const K2: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

    fn init_line(extra: &str) -> String {
        format!(
            r#"{{"command":"init","parameters":{{"period_ms":50,"max_jitter_ms":5,"pair_window_ms":20,"max_pending":4,"keys":{{"cam1":"{K1}","cam2":"{K2}"}}{extra}}}}}"#
        )
    }

    #[test]
    fn parses_init_with_default_persist_interval() {
        let Command::Init { config, keys } = parse(&init_line("")).unwrap() else { panic!() };
        assert_eq!(config.persist_interval, DEFAULT_PERSIST_INTERVAL);
        assert_eq!(config.max_pending, 4);
        assert_eq!(keys[Camera::Cam2][0], 0x20);
    }

    #[test]
    fn persist_interval_accepts_full_u32_range() {
        let Command::Init { config, .. } = parse(&init_line(r#","persist_interval":4294967295"#)).unwrap()
        else {
            panic!()
        };
        assert_eq!(config.persist_interval, u32::MAX);
        assert!(parse(&init_line(r#","persist_interval":0"#)).is_err());
        assert!(parse(&init_line(r#","persist_interval":4294967296"#)).is_err());
    }

    #[test]
    fn rejects_out_of_range_and_mistyped_parameters() {
        let bad = [
            init_line("").replace("\"period_ms\":50", "\"period_ms\":0"),
            init_line("").replace("\"period_ms\":50", "\"period_ms\":60001"),
            init_line("").replace("\"period_ms\":50", "\"period_ms\":50.0"),
            init_line("").replace("\"period_ms\":50", "\"period_ms\":\"50\""),
            init_line("").replace("\"max_jitter_ms\":5", "\"max_jitter_ms\":50"),
            init_line("").replace("\"pair_window_ms\":20", "\"pair_window_ms\":-1"),
            init_line("").replace("\"max_pending\":4", "\"max_pending\":1025"),
            init_line("").replace(K1, "0001"),
            init_line("").replace(K1, &K1.replace('0', "g")),
            init_line("").replace(",\"cam2\"", ",\"cam3\":\"00\",\"cam2\""),
        ];
        for line in bad {
            assert!(parse(&line).is_err(), "accepted {line}");
        }
    }

    #[test]
    fn rejects_malformed_commands() {
        for line in [
            "",
            "not json",
            "[]",
            r#"{"parameters":{}}"#,
            r#"{"command":7}"#,
            r#"{"command":"launch","parameters":{}}"#,
            r#"{"command":"get_state","parameters":[]}"#,
            r#"{"command":"receive","parameters":{}}"#,
            r#"{"command":"receive","parameters":{"frame":12}}"#,
            r#"{"command":"add_key","parameters":{"camera":"cam3","key_id":1,"key":"00"}}"#,
            r#"{"command":"revoke_key","parameters":{"camera":"cam1","key_id":256}}"#,
        ] {
            assert!(parse(line).is_err(), "accepted {line}");
        }
    }

    #[test]
    fn parameters_may_be_omitted_when_none_are_needed() {
        assert_eq!(parse(r#"{"command":"get_state"}"#).unwrap(), Command::GetState);
        assert_eq!(parse(r#"{"command":"restart","parameters":{}}"#).unwrap(), Command::Restart);
    }
}
