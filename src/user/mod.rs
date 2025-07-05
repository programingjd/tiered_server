use crate::env::ConfigurationKey::{AdminUsers, ValidationTotpSecret};
use crate::env::secret_value;
use crate::norm::{
    DEFAULT_COUNTRY_CODE, normalize_email, normalize_first_name, normalize_last_name,
    normalize_phone_number,
};
use crate::otp::Otp;
use crate::otp::action::Event;
use crate::server::DOMAIN_APEX;
use crate::store::Snapshot;
use base64_simd::URL_SAFE_NO_PAD;
use futures::StreamExt;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;
use tracing::{info, trace};

mod endpoints;
pub(crate) mod handler;

#[derive(Clone, Serialize, Deserialize)]
pub struct Email {
    pub(crate) address: String,
    pub(crate) normalized_address: String,
}

impl From<String> for Email {
    fn from(value: String) -> Self {
        Self {
            normalized_address: normalize_email(&value),
            address: value,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Sms {
    number: String,
    normalized_number: String,
}

impl From<String> for Sms {
    fn from(value: String) -> Self {
        Self {
            normalized_number: normalize_phone_number(&value, *DEFAULT_COUNTRY_CODE),
            number: value,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum IdentificationMethod {
    Email(Email),
    Sms(Sms),
    NotSet,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub identification: Vec<IdentificationMethod>,
    pub last_name: String,
    pub last_name_norm: String,
    pub first_name: String,
    pub first_name_norm: String,
    pub date_of_birth: u32,
    #[serde(skip_serializing_if = "is_default", default = "Default::default")]
    pub admin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    t == &T::default()
}

impl User {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn create(
        email: String,
        email_norm: Option<String>,
        last_name: String,
        last_name_norm: Option<String>,
        first_name: String,
        first_name_norm: Option<String>,
        date_of_birth: u32, // yyyyMMdd
        admin: bool,
        needs_validation: bool,
        skip_notification: bool,
        snapshot: &Arc<Snapshot>,
        server_name: &Arc<String>,
    ) -> Option<Self> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let id = Self::new_id(timestamp);
        let identification = vec![IdentificationMethod::Email(Email {
            normalized_address: email_norm.unwrap_or_else(|| normalize_email(&email)),
            address: email,
        })];
        let key = format!("{}/{id}", if needs_validation { "reg" } else { "acc" });
        if snapshot.get::<User>(key.as_str()).is_some() {
            return None;
        }
        let first_name_norm =
            first_name_norm.unwrap_or_else(|| normalize_first_name(first_name.as_str()));
        let last_name_norm =
            last_name_norm.unwrap_or_else(|| normalize_last_name(last_name.as_str()));
        let user = Self {
            id,
            identification,
            last_name,
            last_name_norm,
            first_name,
            first_name_norm,
            date_of_birth,
            admin,
            metadata: if needs_validation {
                Some(json!({"timestamp": timestamp}))
            } else {
                None
            },
        };
        Snapshot::set_and_wait_for_update(key.as_str(), &user).await?;
        if !needs_validation && !skip_notification {
            Otp::send(&user, Event::FirstLogin, None, snapshot, server_name).await?;
        }
        Some(user)
    }
    pub fn email(&self) -> Option<&str> {
        self.identification.iter().find_map(|it| {
            if let IdentificationMethod::Email(email) = it {
                Some(email.normalized_address.as_str())
            } else {
                None
            }
        })
    }
    pub fn emails(&self) -> impl Iterator<Item = &str> {
        self.identification.iter().filter_map(|it| {
            if let IdentificationMethod::Email(email) = it {
                Some(email.normalized_address.as_str())
            } else {
                None
            }
        })
    }
    pub fn sms_number(&self) -> Option<&str> {
        self.identification.iter().find_map(|it| {
            if let IdentificationMethod::Sms(number) = it {
                Some(number.normalized_number.as_str())
            } else {
                None
            }
        })
    }
    pub fn sms_numbers(&self) -> impl Iterator<Item = &str> {
        self.identification.iter().filter_map(|it| {
            if let IdentificationMethod::Sms(number) = it {
                Some(number.normalized_number.as_str())
            } else {
                None
            }
        })
    }
    pub fn new_id(timestamp: u32) -> String {
        let mut random = [0u8; 36];
        random[32..].copy_from_slice(timestamp.to_be_bytes().as_slice());
        SystemRandom::new().fill(&mut random[..32]).unwrap();
        URL_SAFE_NO_PAD.encode_to_string(
            timestamp
                .to_le_bytes()
                .into_iter()
                .chain(random)
                .collect::<Vec<_>>(),
        )
    }
}

pub(crate) async fn ensure_admin_users_exist(snapshot: &Arc<Snapshot>) -> Option<()> {
    let value = secret_value(AdminUsers).unwrap_or("");
    let users = snapshot
        .list::<User>("acc/")
        .map(|(_, user)| user)
        .collect::<Vec<_>>();
    trace!(
        "users:\n{}",
        users
            .iter()
            .map(|it| format!(
                "    {} {} {}",
                it.identification
                    .iter()
                    .find_map(|it| match it {
                        IdentificationMethod::Email(email) => Some(email.address.as_str()),
                        _ => None,
                    })
                    .unwrap_or("?"),
                it.last_name.as_str(),
                it.first_name.as_str()
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
    for user in value.split(";") {
        let mut iter = user.split(",");
        let email = iter.next()?;
        let last_name = iter.next()?;
        let first_name = iter.next()?;
        let date_of_birth = iter.next()?.parse::<u32>().ok()?;
        let email_norm = normalize_email(email);
        let last_name_norm = normalize_last_name(last_name);
        let first_name_norm = normalize_first_name(first_name);
        if !users.iter().any(|user| {
            user.identification.iter().any(|it| match it {
                IdentificationMethod::Email(Email {
                    normalized_address, ..
                }) => {
                    normalized_address == &email_norm
                        && user.last_name_norm == last_name_norm
                        && user.first_name_norm == first_name_norm
                        && user.date_of_birth == date_of_birth
                }
                _ => false,
            })
        }) {
            info!("new admin account: {email} {last_name} {first_name}");
            let server_name = DOMAIN_APEX.to_string();
            User::create(
                email.trim().to_string(),
                None,
                last_name.trim().to_string(),
                None,
                first_name.trim().to_string(),
                None,
                date_of_birth,
                true,
                false,
                true,
                snapshot,
                &Arc::new(server_name),
            )
            .await?;
        }
    }
    Some(())
}

//noinspection SpellCheckingInspection
pub(crate) static VALIDATION_TOTP_SECRET: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(ValidationTotpSecret));
