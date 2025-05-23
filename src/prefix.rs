use crate::env::ConfigurationKey::{ApiPathPrefix, UserPathPrefix};
use crate::env::{ConfigurationKey, secret_value};
use std::sync::LazyLock;

pub struct Prefix {
    pub with_trailing_slash: &'static str,
    pub without_trailing_slash: &'static str,
}

impl Prefix {
    pub fn matches(&self, path: &str) -> bool {
        path == self.without_trailing_slash || path.starts_with(self.with_trailing_slash)
    }
}

pub static API_PATH_PREFIX: LazyLock<Prefix> = LazyLock::new(|| from_env(ApiPathPrefix, "/api/"));

pub static USER_PATH_PREFIX: LazyLock<Prefix> =
    LazyLock::new(|| from_env(UserPathPrefix, "/user/"));

fn from_env(key: ConfigurationKey, default: &'static str) -> Prefix {
    let with_trailing_slash = secret_value(key)
        .map(|prefix| {
            let prefix: &'static str = if prefix.ends_with("/") {
                prefix.to_string().leak()
            } else {
                format!("{prefix}/").leak()
            };
            prefix
        })
        .unwrap_or(default);
    Prefix {
        with_trailing_slash,
        without_trailing_slash: &with_trailing_slash[..with_trailing_slash.len() - 1],
    }
}
