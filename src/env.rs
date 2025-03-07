use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Read;
use std::sync::LazyLock;

static FILE: LazyLock<BTreeMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut map = BTreeMap::<&'static str, &'static str>::new();
    if let Ok(content) = File::open("./.env").and_then(|ref mut it| {
        let mut content = String::new();
        it.read_to_string(&mut content).map(|_| content)
    }) {
        content
            .split('\n')
            .filter(|&line| line.trim_start().starts_with('#'))
            .for_each(|line| {
                let mut parts = line.split('=');
                if let Some(key) = parts.next() {
                    if let Some(value) = parts.next() {
                        map.insert(
                            key.trim().to_string().leak(),
                            value.trim().to_string().leak(),
                        );
                    }
                }
            })
    }
    map
});

static ENV: LazyLock<HashMap<ConfigurationKey, &'static str>> = LazyLock::new(|| {
    let mut map = HashMap::<ConfigurationKey, &'static str>::new();
    ConfigurationKey::all().for_each(|it| {
        if let Some(ref value) = std::env::var_os(it.name()) {
            if let Some(v) = value.to_str() {
                map.insert(it, v.to_string().leak());
            }
        }
    });
    map
});

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub(crate) enum ConfigurationKey {
    DomainApex,
    BindAddress,
    StaticGithubUser,
    StaticGithubRepository,
    StaticGithubBranch,
    StaticGithubWebhookToken,
    S3Region,
    S3Endpoint,
    S3Bucket,
    S3AccessKey,
    S3SecretKey,
    StoreEncryptionKey,
    OtpSigningKey,
    ApiPathPrefix,
    UserPathPrefix,
    LoginPath,
    IdentificationHashPrefix,
    UserHashPrefix,
    AdminUsers,
}

impl ConfigurationKey {
    fn all() -> impl Iterator<Item = Self> {
        [Self::BindAddress].into_iter()
    }
    fn name(&self) -> &'static str {
        match self {
            Self::DomainApex => "DOMAIN_APEX",
            Self::BindAddress => "BIND_ADDRESS",
            Self::StaticGithubUser => "STATIC_GITHUB_USER",
            Self::StaticGithubRepository => "STATIC_GITHUB_REPOSITORY",
            Self::StaticGithubBranch => "STATIC_GITHUB_BRANCH",
            Self::StaticGithubWebhookToken => "STATIC_GITHUB_WEBHOOK_TOKEN",
            Self::S3Region => "S3_REGION",
            Self::S3Endpoint => "S3_ENDPOINT",
            Self::S3Bucket => "S3_BUCKET",
            Self::S3AccessKey => "S3_ACCESS_KEY",
            Self::S3SecretKey => "S3_SECRET_KEY",
            Self::StoreEncryptionKey => "STORE_ENCRYPTION_KEY",
            Self::OtpSigningKey => "OTP_SIGNING_KEY",
            Self::ApiPathPrefix => "API_PATH_PREFIX",
            Self::UserPathPrefix => "USER_PATH_PREFIX",
            Self::LoginPath => "LOGIN_PATH",
            Self::IdentificationHashPrefix => "IDENTIFICATION_HASH_PREFIX",
            Self::UserHashPrefix => "USER_HASH_PREFIX",
            Self::AdminUsers => "ADMIN_USERS",
        }
    }
}

pub(crate) fn secret_value(key: ConfigurationKey) -> Option<&'static str> {
    match ENV.get(&key).or_else(|| FILE.get(key.name())) {
        Some(value) => Some(*value),
        None => None,
    }
}
