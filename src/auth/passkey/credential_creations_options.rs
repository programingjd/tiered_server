use crate::auth::passkey::credentials::Credentials;
use crate::server::DOMAIN_TITLE;
use crate::user::User;
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct CredentialCreationOptions {
    pub challenge: String,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<Credentials>,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    pub rp: Rp,
    pub user: UserId,
}

#[derive(Serialize)]
pub(crate) struct UserId {
    id: String,
    #[serde(rename = "displayName")]
    display_name: String,
    name: String,
}

impl From<&User> for UserId {
    fn from(user: &User) -> Self {
        Self {
            id: user.id.clone(),
            display_name: user.first_name.clone(),
            name: format!("{} {}", user.first_name, user.last_name),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct PubKeyCredParams {
    alg: i16,
    #[serde(rename = "type")]
    typ: &'static str,
}

impl PubKeyCredParams {
    pub fn ed25519() -> Self {
        Self {
            alg: -8,
            typ: "public-key",
        }
    }
    pub fn es256() -> Self {
        Self {
            alg: -7,
            typ: "public-key",
        }
    }
    pub fn rs256() -> Self {
        Self {
            alg: -257,
            typ: "public-key",
        }
    }
}

#[derive(Serialize)]
pub(crate) struct Rp {
    name: &'static str,
}

impl Default for Rp {
    fn default() -> Self {
        Self {
            name: *DOMAIN_TITLE,
        }
    }
}
