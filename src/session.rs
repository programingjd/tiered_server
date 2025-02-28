use basic_cookies::Cookie;
use hyper::HeaderMap;
use hyper::header::COOKIE;
use hyper::http::HeaderValue;
use serde::{Deserialize, Serialize};
use std::default::Default;

#[derive(Serialize, Deserialize)]
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

impl SessionState {
    pub(crate) fn from_headers(headers: &HeaderMap<HeaderValue>) -> SessionState {
        let cookie_value = headers.get(COOKIE);
        if cookie_value.is_none() {
            return SessionState::Missing;
        }
        let cookie_value = cookie_value
            .and_then(|it| it.to_str().ok())
            .and_then(|it| Cookie::parse(it).ok())
            .and_then(|it| {
                it.iter().find_map(|it| {
                    if it.get_name() == "user_session" {
                        Some(it.get_value())
                    } else {
                        None
                    }
                })
            });
        if cookie_value.is_none() {
            return SessionState::Corrupted;
        }
        SessionState::Corrupted
    }
}
