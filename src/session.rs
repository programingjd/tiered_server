use crate::env::ConfigurationKey::{LoginPath, UserPathPrefix};
use crate::env::secret_value;
use crate::store::Snapshot;
use base64_simd::URL_SAFE_NO_PAD;
use basic_cookies::Cookie;
use hyper::HeaderMap;
use hyper::header::COOKIE;
use hyper::http::HeaderValue;
use pinboard::NonEmptyPinboard;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::default::Default;
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;

const MAX_AGE: u32 = 14_400; // 4h

pub(crate) static LOGIN_PATH: LazyLock<&str> =
    LazyLock::new(|| secret_value(LoginPath).unwrap_or("/login"));

pub(crate) const SID_EXPIRED: HeaderValue =
    HeaderValue::from_static("st=0; Secure; SameSite=Strict");

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct User {
    email: String,
    display_name: String,
    #[serde(skip_serializing_if = "is_default")]
    admin: bool,
}

pub(crate) enum SessionState {
    Missing,
    Corrupted,
    Expired { user: User },
    Valid { user: User },
}

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    t == &T::default()
}

#[derive(Serialize, Deserialize)]
struct Session {
    user: User,
    timestamp: u32,
}

impl User {
    pub(crate) async fn create_session(&self) -> Option<()> {
        let user = self.clone();
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let session = Session { user, timestamp };
        let mut random = [0u8; 32];
        SystemRandom::new().fill(&mut random).unwrap();
        let session_id = URL_SAFE_NO_PAD.encode_to_string(
            timestamp
                .to_le_bytes()
                .into_iter()
                .chain(random.into_iter())
                .collect::<Vec<_>>(),
        );
        let key = format!("/sid/{session_id}");
        Snapshot::set(key.as_str(), &session).await
    }
}

impl SessionState {
    pub(crate) async fn from_headers(
        headers: &HeaderMap<HeaderValue>,
        store_cache: Arc<NonEmptyPinboard<Snapshot>>,
    ) -> SessionState {
        let cookie_value = headers.get_all(COOKIE).iter().find_map(|it| {
            it.to_str()
                .ok()
                .and_then(|it| Cookie::parse(it).ok())
                .and_then(|it| {
                    it.iter().find_map(|it| {
                        if it.get_name() == "sid" {
                            Some(it.get_value())
                        } else {
                            None
                        }
                    })
                })
        });
        if cookie_value.is_none() {
            SessionState::Missing
        } else {
            let session_id = cookie_value.unwrap();
            if let Some(session) = store_cache
                .get_ref()
                .get::<Session>(&format!("/sid/{session_id}"))
            {
                let user = session.user;
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as u32
                    - 180;
                if session.timestamp < now && now - session.timestamp < MAX_AGE {
                    SessionState::Valid { user }
                } else {
                    SessionState::Expired { user }
                }
            } else {
                SessionState::Missing
            }
        }
    }
}
