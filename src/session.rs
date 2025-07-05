use crate::env::ConfigurationKey::LoginPath;
use crate::env::secret_value;
use crate::store::Snapshot;
use crate::user::User;
use base64_simd::URL_SAFE_NO_PAD;
use basic_cookies::Cookie;
use hyper::HeaderMap;
use hyper::header::COOKIE;
use hyper::http::HeaderValue;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;
use tracing::debug;

pub(crate) const SESSION_MAX_AGE: u32 = 14_400; // 4h

pub(crate) static LOGIN_PATH: LazyLock<&str> =
    LazyLock::new(|| secret_value(LoginPath).unwrap_or("/login"));

pub(crate) const SID_EXPIRED: HeaderValue =
    HeaderValue::from_static("st=0; Path=/; Secure; SameSite=Strict; Max-Age=34560000");
pub(crate) const DELETE_ST_COOKIES: HeaderValue = HeaderValue::from_static(
    "st=0; Path=/; Secure; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
);
pub(crate) const DELETE_SID_COOKIES: HeaderValue = HeaderValue::from_static(
    "sid=0; Path=/; Secure; HttpOnly; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
);

pub enum SessionState {
    Missing,
    Expired {
        #[allow(dead_code)]
        user: User,
    },
    Valid {
        user: User,
        session: Session,
    },
}

impl SessionState {
    pub fn is_admin(&self) -> bool {
        match self {
            SessionState::Valid { user, .. } => user.admin,
            _ => false,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Session {
    pub(crate) id: String,
    pub user_id: String,
    pub passkey_id: Option<String>,
    pub timestamp: u32,
    pub delegated: bool,
}

impl Session {
    pub(crate) fn cookies(&self, cross_site: bool) -> [HeaderValue; 2] {
        let sid_cookie = format!(
            "sid={}; Path=/; Secure; HttpOnly; SameSite={}; Max-Age=34560000",
            self.id,
            if cross_site { "Lax" } else { "Strict" }
        );
        debug!("cookie: {}", sid_cookie);
        let st_cookie = format!(
            "st={}; Path=/; Secure; SameSite={}; Max-Age=34560000",
            self.timestamp + SESSION_MAX_AGE,
            if cross_site { "Lax" } else { "Strict" }
        );
        debug!("cookie: {}", st_cookie);
        [
            HeaderValue::try_from(sid_cookie).unwrap(),
            HeaderValue::try_from(st_cookie).unwrap(),
        ]
    }
}

impl User {
    pub async fn create_session(
        user_id: impl Into<String>,
        snapshot: &Arc<Snapshot>,
        passkey_id: Option<String>,
        delegated: bool,
    ) -> Option<Session> {
        let user_id = user_id.into();
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let mut random = [0u8; 36];
        random[32..].copy_from_slice(timestamp.to_be_bytes().as_slice());
        SystemRandom::new().fill(&mut random[..32]).unwrap();
        let session_id = URL_SAFE_NO_PAD.encode_to_string(random);
        // delete all previous sessions for the user unless they are with a different passkey
        let session_keys = snapshot
            .list::<Session>("sid/")
            .filter_map(|(key, session)| {
                if let Some(ref passkey_id) = passkey_id {
                    if let Some(ref session_passkey_id) = session.passkey_id {
                        if session_passkey_id == passkey_id.as_str() {
                            Some(key.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else if user_id == session.user_id {
                    Some(key.to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Snapshot::delete_and_return_before_update(session_keys.iter()).await;
        debug!("new session for user {user_id} @{timestamp}");
        let session = Session {
            id: session_id,
            user_id,
            passkey_id,
            timestamp,
            delegated,
        };
        let key = format!("sid/{}", session.id);
        Snapshot::set_and_wait_for_update(key.as_str(), &session).await?;
        Some(session)
    }
}

impl SessionState {
    pub fn from_headers(
        headers: &HeaderMap<HeaderValue>,
        snapshot: &Arc<Snapshot>,
    ) -> SessionState {
        let cookie_value = headers.get_all(COOKIE).iter().find_map(|it| {
            it.to_str()
                .inspect_err(|_| debug!("invalid cookie: {}", it.as_bytes().escape_ascii()))
                .ok()
                .and_then(|it| {
                    Cookie::parse(it)
                        .inspect_err(|_| debug!("invalid cookie value: {it}"))
                        .ok()
                })
                .and_then(|it| {
                    it.iter().find_map(|it| {
                        debug!("cookie: {}={}", it.get_name(), it.get_value());
                        if it.get_name() == "sid" {
                            Some(it.get_value())
                        } else {
                            None
                        }
                    })
                })
        });
        if cookie_value.is_none() {
            debug!("session cookie is missing");
            SessionState::Missing
        } else {
            let session_id = cookie_value.unwrap();
            if let Some(session) = snapshot.get::<Session>(&format!("sid/{session_id}")) {
                let user_id = &session.user_id;
                if let Some(user) = snapshot.get::<User>(&format!("acc/{user_id}")) {
                    let now = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as u32
                        - 180;
                    if session.timestamp > 0
                        && session.timestamp - 180 <= now
                        && now < session.timestamp + SESSION_MAX_AGE
                    {
                        debug!(
                            "session is valid: {} in [{}, {}]",
                            session.timestamp,
                            now,
                            session.timestamp + SESSION_MAX_AGE
                        );
                        SessionState::Valid { user, session }
                    } else {
                        debug!(
                            "session expired: {} !in [{}, {}]",
                            session.timestamp,
                            now,
                            session.timestamp + SESSION_MAX_AGE
                        );
                        SessionState::Expired { user }
                    }
                } else {
                    debug!("user is missing");
                    SessionState::Missing
                }
            } else {
                debug!("session is missing");
                SessionState::Missing
            }
        }
    }
}
