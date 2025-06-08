use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Read;
use std::sync::LazyLock;
use tracing::info;

static FILE: LazyLock<BTreeMap<&'static str, &'static str>> = LazyLock::new(|| {
    let mut map = BTreeMap::<&'static str, &'static str>::new();
    if let Ok(content) = File::open("./.env").and_then(|ref mut it| {
        let mut content = String::new();
        it.read_to_string(&mut content).map(|_| content)
    }) {
        content
            .split('\n')
            .filter(|&line| !line.trim_start().starts_with('#'))
            .for_each(|line| {
                let mut parts = line.split('=');
                if let Some(key) = parts.next() {
                    if let Some(value) = parts.next() {
                        info!("{key} loaded from environment file");
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
                info!("{} loaded from environment variable", it.name());
                map.insert(it, v.to_string().leak());
            }
        }
    });
    map
});

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub enum ConfigurationKey {
    DomainApex,
    DomainTitle,
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
    ChallengeSigningKey,
    ApiPathPrefix,
    UserPathPrefix,
    LoginPath,
    ValidationTotpSecret,
    DefaultCountryCode,
    EmailApiEndpoint,
    EmailApiAuthHeader,
    EmailApiAuthToken,
    EmailApiMethod,
    EmailApiRequestContentType,
    EmailSendAddress,
    EmailOneTimeLoginTitle,
    EmailOneTimeLoginTemplate,
    EmailAccountCreatedTitle,
    EmailAccountCreatedTemplate,
    AdminUsers,
    Other { variable_name: &'static str },
}

impl ConfigurationKey {
    fn all() -> impl Iterator<Item = Self> {
        [
            Self::DomainApex,
            Self::DomainTitle,
            Self::BindAddress,
            Self::StaticGithubUser,
            Self::StaticGithubRepository,
            Self::StaticGithubBranch,
            Self::StaticGithubWebhookToken,
            Self::S3Region,
            Self::S3Endpoint,
            Self::S3Bucket,
            Self::S3AccessKey,
            Self::S3SecretKey,
            Self::StoreEncryptionKey,
            Self::OtpSigningKey,
            Self::ChallengeSigningKey,
            Self::ApiPathPrefix,
            Self::UserPathPrefix,
            Self::LoginPath,
            Self::ValidationTotpSecret,
            Self::DefaultCountryCode,
            Self::EmailApiEndpoint,
            Self::EmailApiAuthHeader,
            Self::EmailApiAuthToken,
            Self::EmailApiMethod,
            Self::EmailApiRequestContentType,
            Self::EmailSendAddress,
            Self::EmailOneTimeLoginTitle,
            Self::EmailOneTimeLoginTemplate,
            Self::EmailAccountCreatedTitle,
            Self::EmailAccountCreatedTemplate,
            Self::AdminUsers,
        ]
        .into_iter()
    }
    fn name(&self) -> &'static str {
        match self {
            Self::DomainApex => "DOMAIN_APEX",
            Self::DomainTitle => "DOMAIN_TITLE",
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
            Self::ChallengeSigningKey => "CHALLENGE_SIGNING_KEY",
            Self::ApiPathPrefix => "API_PATH_PREFIX",
            Self::UserPathPrefix => "USER_PATH_PREFIX",
            Self::LoginPath => "LOGIN_PATH",
            Self::ValidationTotpSecret => "VALIDATION_TOTP_SECRET",
            Self::DefaultCountryCode => "DEFAULT_COUNTRY_CODE",
            Self::EmailApiEndpoint => "EMAIL_API_ENDPOINT",
            Self::EmailApiAuthHeader => "EMAIL_API_AUTH_HEADER",
            Self::EmailApiAuthToken => "EMAIL_API_AUTH_TOKEN",
            Self::EmailApiMethod => "EMAIL_API_METHOD",
            Self::EmailApiRequestContentType => "EMAIL_API_REQUEST_CONTENT_TYPE",
            Self::EmailSendAddress => "EMAIL_SEND_ADDRESS",
            Self::EmailOneTimeLoginTitle => "EMAIL_ONE_TIME_LOGIN_TITLE",
            Self::EmailOneTimeLoginTemplate => "EMAIL_ONE_TIME_LOGIN_TEMPLATE",
            Self::EmailAccountCreatedTitle => "EMAIL_ACCOUNT_CREATED_TITLE",
            Self::EmailAccountCreatedTemplate => "EMAIL_ACCOUNT_CREATED_TEMPLATE",
            Self::AdminUsers => "ADMIN_USERS",
            Self::Other { variable_name } => variable_name,
        }
    }
}

pub fn secret_value(key: ConfigurationKey) -> Option<&'static str> {
    match ENV.get(&key).or_else(|| FILE.get(key.name())) {
        Some(value) => Some(*value),
        None => None,
    }
}
