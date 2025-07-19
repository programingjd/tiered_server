use crate::env::ConfigurationKey::{
    EmailAddEmailTemplate, EmailAddEmailTitle, EmailUpdateEmailTemplate, EmailUpdateEmailTitle,
};
use crate::env::secret_value;
use crate::prefix::API_PATH_PREFIX;
use crate::store::Snapshot;
use crate::user::{Email, IdentificationMethod, User};
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{Either, Empty, Full};
use hyper::Response;
use hyper::body::Bytes;
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use tracing::info;

//noinspection SpellCheckingInspection
static EMAIL_ADD_EMAIL_TITLE: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailAddEmailTitle));
//noinspection SpellCheckingInspection
static EMAIL_ADD_EMAIL_TEMPLATE: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailAddEmailTemplate));

//noinspection SpellCheckingInspection
static EMAIL_UPDATE_EMAIL_TITLE: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailUpdateEmailTitle));
//noinspection SpellCheckingInspection
static EMAIL_UPDATE_EMAIL_TEMPLATE: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailUpdateEmailTemplate));

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailUpdate {
    pub normalized_old_address: String,
    pub normalized_new_address: String,
    pub new_address: String,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailAddition {
    pub normalized_new_address: String,
    pub new_address: String,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Action {
    #[serde(rename = "update_email")]
    UpdateEmail(EmailUpdate),
    #[serde(rename = "add_email")]
    AddEmail(EmailAddition),
}

impl Action {
    pub(crate) fn validity_duration(&self) -> Option<u32> {
        match self {
            Action::AddEmail(_) | Action::UpdateEmail(_) => Some(1_200), // 20 mins
        }
    }
    pub(crate) fn email_template(&self) -> (Option<&'static str>, Option<&'static str>) {
        match self {
            Self::AddEmail(_) => (*EMAIL_ADD_EMAIL_TITLE, *EMAIL_ADD_EMAIL_TEMPLATE),
            Self::UpdateEmail(_) => (*EMAIL_UPDATE_EMAIL_TITLE, *EMAIL_UPDATE_EMAIL_TEMPLATE),
        }
    }
    pub(crate) fn id(&self) -> String {
        id(self.email())
    }
    pub(crate) fn email(&self) -> &str {
        match self {
            Action::AddEmail(EmailAddition {
                normalized_new_address,
                ..
            }) => normalized_new_address.as_str(),
            Action::UpdateEmail(EmailUpdate {
                normalized_new_address,
                ..
            }) => normalized_new_address.as_str(),
        }
    }
    pub(crate) async fn handle(
        self,
        mut user: User,
    ) -> Option<Response<Either<Full<Bytes>, Empty<Bytes>>>> {
        match self {
            Action::AddEmail(EmailAddition {
                new_address,
                normalized_new_address,
            }) => {
                // we only add the new address if it doesn't already exist
                if !user.identification.iter().any(|it| match it {
                    IdentificationMethod::Email(Email {
                        normalized_address, ..
                    }) => normalized_address == &normalized_new_address,
                    _ => false,
                }) {
                    user.identification.push(IdentificationMethod::Email(Email {
                        address: new_address,
                        normalized_address: normalized_new_address,
                    }));
                    if Snapshot::set_and_wait_for_update(&format!("acc/{}", user.id), &user)
                        .await
                        .is_some()
                    {
                        info!("202 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
                        Some(
                            Response::builder()
                                .status(204)
                                .body(Either::Right(Empty::new()))
                                .unwrap(),
                        )
                    } else {
                        None
                    }
                } else {
                    info!("202 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
                    Some(
                        Response::builder()
                            .status(204)
                            .body(Either::Right(Empty::new()))
                            .unwrap(),
                    )
                }
            }
            Action::UpdateEmail(EmailUpdate {
                normalized_old_address,
                normalized_new_address,
                new_address,
            }) => {
                // if the new address already exists, we remove the old address (if it exists)
                if user.identification.iter().any(|it| match it {
                    IdentificationMethod::Email(Email {
                        normalized_address, ..
                    }) => normalized_address == &normalized_new_address,
                    _ => false,
                }) {
                    user.identification.retain(|it| match it {
                        IdentificationMethod::Email(Email {
                            normalized_address, ..
                        }) => normalized_address != &normalized_old_address,
                        _ => true,
                    });
                    if Snapshot::set_and_wait_for_update(&format!("acc/{}", user.id), &user)
                        .await
                        .is_some()
                    {
                        info!("202 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
                        Some(
                            Response::builder()
                                .status(204)
                                .body(Either::Right(Empty::new()))
                                .unwrap(),
                        )
                    } else {
                        None
                    }
                }
                // if the old address exists, we replace it with the new address
                else if let Some(identification) =
                    user.identification.iter_mut().find(|it| match it {
                        IdentificationMethod::Email(Email {
                            normalized_address, ..
                        }) => normalized_address == &normalized_old_address,
                        _ => false,
                    })
                {
                    *identification = IdentificationMethod::Email(Email {
                        address: new_address,
                        normalized_address: normalized_new_address,
                    });
                    if Snapshot::set_and_wait_for_update(&format!("acc/{}", user.id), &user)
                        .await
                        .is_some()
                    {
                        info!("202 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
                        Some(
                            Response::builder()
                                .status(204)
                                .body(Either::Right(Empty::new()))
                                .unwrap(),
                        )
                    } else {
                        None
                    }
                } else {
                    info!("202 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
                    Some(
                        Response::builder()
                            .status(204)
                            .body(Either::Right(Empty::new()))
                            .unwrap(),
                    )
                }
            }
        }
    }
}

fn id(normalized_email_address: &str) -> String {
    URL_SAFE_NO_PAD.encode_to_string(digest(&SHA256, normalized_email_address.as_bytes()).as_ref())
}
