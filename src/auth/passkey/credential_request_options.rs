use crate::auth::passkey::credentials::Credentials;
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct CredentialRequestOptions {
    pub challenge: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<Credentials>,
}
