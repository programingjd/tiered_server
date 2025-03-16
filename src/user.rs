use crate::env::ConfigurationKey::{AdminUsers, IdentificationHashPrefix};
use crate::env::secret_value;
use crate::otp::Otp;
use crate::store::Snapshot;
use base64_simd::URL_SAFE_NO_PAD;
use ring::digest::{Context, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use std::time::SystemTime;
use zip_static_handler::handler::Handler;

//noinspection SpellCheckingInspection
static IDENTIFICATION_HASH_PREFIX: LazyLock<&'static str> =
    LazyLock::new(|| secret_value(IdentificationHashPrefix).unwrap_or("4*cf_@"));

#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum IdentificationMethod {
    Email(String),
    Sms(String),
    NotSet,
}

impl IdentificationMethod {
    pub(crate) fn hash(&self) -> String {
        let mut digest = Context::new(&SHA256);
        digest.update(IDENTIFICATION_HASH_PREFIX.as_bytes());
        match self {
            Self::Email(address) => {
                digest.update("email:".as_bytes());
                digest.update(address.as_bytes());
            }
            Self::Sms(number) => {
                digest.update("sms:".as_bytes());
                digest.update(number.as_bytes());
            }
            Self::NotSet => digest.update("none".as_bytes()),
        }
        let hash = digest.finish();
        URL_SAFE_NO_PAD.encode_to_string(hash.as_ref())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct User {
    pub(crate) id: String,
    pub(crate) identification: IdentificationMethod,
    pub(crate) first_name: String,
    pub(crate) last_name: String,
    pub(crate) date_of_birth: u32,
    #[serde(skip_serializing_if = "is_default")]
    pub(crate) admin: bool,
}

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    t == &T::default()
}

pub(crate) async fn ensure_admin_users_exist(snapshot: &Snapshot, handler: &Handler) -> Option<()> {
    let value = secret_value(AdminUsers).unwrap_or("");
    for user in value.split(";") {
        let mut iter = user.split(",");
        let email = iter.next()?;
        let first_name = iter.next()?;
        let last_name = iter.next()?;
        let date_of_birth = iter.next()?.parse::<u32>().ok()?;
        if let Some(user) = User::create(
            email.to_string(),
            first_name.to_string(),
            last_name.to_string(),
            date_of_birth,
            true,
            snapshot,
        )
        .await
        {
            Otp::send(user, snapshot, handler).await?;
        }
    }
    Some(())
}

impl User {
    pub(crate) async fn create(
        email: String,
        first_name: String,
        last_name: String,
        date_of_birth: u32, // yyyyMMdd
        admin: bool,
        store_cache: &Snapshot,
    ) -> Option<Self> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let mut random = [0u8; 36];
        random[32..].copy_from_slice(timestamp.to_be_bytes().as_slice());
        SystemRandom::new().fill(&mut random[..32]).unwrap();
        let id = URL_SAFE_NO_PAD.encode_to_string(
            timestamp
                .to_le_bytes()
                .into_iter()
                .chain(random.into_iter())
                .collect::<Vec<_>>(),
        );
        let identification = IdentificationMethod::Email(email);
        let hash = identification.hash();
        let key = format!("/pk/{hash}");
        if store_cache.get::<User>(key.as_str()).is_some() {
            return None;
        }
        let user = Self {
            id,
            identification,
            first_name,
            last_name,
            date_of_birth,
            admin,
        };
        Snapshot::set(key.as_str(), &user).await?;
        Some(user)
    }
}
