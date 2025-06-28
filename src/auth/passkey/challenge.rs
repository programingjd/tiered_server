use crate::env::ConfigurationKey::ChallengeSigningKey;
use crate::env::secret_value;
use crate::hex::hex_to_bytes;
use ring::hmac::{HMAC_SHA256, Key, Tag, sign};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Write;
use std::sync::LazyLock;
use std::time::SystemTime;
use tracing::{debug, warn};

//noinspection SpellCheckingInspection
static SIGNING_KEY: LazyLock<&'static str> = LazyLock::new(|| {
    secret_value(ChallengeSigningKey).unwrap_or("4nyZsaw5j1JxMy38uIj5sxHucy7Dh_6KTqQWFq2x94g")
});

const CHALLENGE_VALIDITY_DURATION: u32 = 180; // 3 mins

#[derive(Serialize, Deserialize)]
pub(crate) struct ChallengeMetadata {
    uuid: String,
    metadata: Option<Value>,
}

#[derive(Deserialize)]
pub(crate) struct ClientData<'a> {
    pub challenge: &'a [u8],
}

pub(crate) fn signature(challenge: &[u8]) -> Tag {
    let key = Key::new(HMAC_SHA256, SIGNING_KEY.as_bytes());
    sign(&key, challenge)
}

pub(crate) fn new(challenge_metadata: &ChallengeMetadata) -> Option<Vec<u8>> {
    let mut challenge = Vec::with_capacity(1024);
    let mut part_count = 0_usize;
    for (i, it) in challenge_metadata.uuid.split('-').enumerate() {
        part_count += 1;
        match i {
            0 => {
                if it.len() != 8 {
                    return None;
                } else {
                    challenge = hex_to_bytes(it.as_bytes(), challenge)?;
                }
            }
            1..=3 => {
                if it.len() != 4 {
                    return None;
                } else {
                    challenge = hex_to_bytes(it.as_bytes(), challenge)?;
                }
            }
            4 => {
                if it.len() != 12 {
                    return None;
                } else {
                    challenge = hex_to_bytes(it.as_bytes(), challenge)?;
                }
            }
            _ => return None,
        }
    }
    if part_count != 5 {
        return None;
    }
    challenge.push(0);
    challenge.push(0);
    if let Some(ref metadata) = challenge_metadata.metadata {
        serde_json::to_writer(&mut challenge, metadata).ok()?;
    }
    let len = challenge.len();
    // 16 (uuid) + 2 (json len) + len (json) + 32 (random) + 4 (timestamp) + 32 (signature) = 86 + len
    if len > (u16::MAX - 86) as usize {
        return None;
    }
    let len_bytes = ((len - 18) as u16).to_be_bytes();
    challenge[16] = len_bytes[0];
    challenge[17] = len_bytes[1];
    let mut buf = [0u8; 32];
    SystemRandom::new().fill(&mut buf).unwrap();
    challenge.extend_from_slice(&buf);
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let timestamp_bytes = timestamp.to_be_bytes();
    challenge.push(timestamp_bytes[0]);
    challenge.push(timestamp_bytes[1]);
    challenge.push(timestamp_bytes[2]);
    challenge.push(timestamp_bytes[3]);
    let signature = signature(&challenge);
    challenge.extend_from_slice(signature.as_ref());
    Some(challenge)
}

pub(crate) fn verify(challenge: &[u8], challenge_metadata: &ChallengeMetadata) -> bool {
    if challenge.len() < 70 {
        warn!("challenge too short");
        return false;
    }
    let uuid = &challenge[..16];
    let mut uuid_str = String::new();
    uuid[..4]
        .iter()
        .for_each(|it| write!(uuid_str, "{it:02x}").unwrap());
    uuid_str.push('-');
    uuid[4..6]
        .iter()
        .for_each(|it| write!(uuid_str, "{it:02x}").unwrap());
    uuid_str.push('-');
    uuid[6..8]
        .iter()
        .for_each(|it| write!(uuid_str, "{it:02x}").unwrap());
    uuid_str.push('-');
    uuid[8..10]
        .iter()
        .for_each(|it| write!(uuid_str, "{it:02x}").unwrap());
    uuid_str.push('-');
    uuid[10..]
        .iter()
        .for_each(|it| write!(uuid_str, "{it:02x}").unwrap());
    if uuid_str != challenge_metadata.uuid {
        warn!("challenge uuid mismatch");
        return false;
    }
    let len = u16::from_be_bytes([challenge[16], challenge[17]]) as usize;
    // 16 (uuid) + 2 (json len) + len (json) + 32 (random) + 4 (timestamp) + 32 (signature) = 86 + len
    if challenge.len() != len + 86 {
        warn!("challenge length mismatch");
        return false;
    }
    if len == 0 && challenge_metadata.metadata.is_some() {
        warn!("missing challenge metadata");
        return false;
    }
    if len > 0 && challenge_metadata.metadata.is_none() {
        warn!("unexpected challenge metadata");
        return false;
    }
    if len > 0 {
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&challenge[38..]) {
            let metadata = challenge_metadata.metadata.as_ref().unwrap();
            if &value != metadata {
                warn!("challenge metadata mismatch");
                return false;
            }
        } else {
            warn!("challenge metadata mismatch");
        }
    }
    let timestamp: [u8; 4] = challenge[50 + len..54 + len].try_into().unwrap();
    let timestamp = u32::from_be_bytes(timestamp);
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let elapsed = now - timestamp;
    if timestamp > now || elapsed > CHALLENGE_VALIDITY_DURATION {
        debug!("challenge expired {now} - {timestamp} = {elapsed} > {CHALLENGE_VALIDITY_DURATION}");
        false
    } else {
        let signature = signature(&challenge[..len + 54]);
        signature.as_ref() == &challenge[len + 54..]
    }
}
