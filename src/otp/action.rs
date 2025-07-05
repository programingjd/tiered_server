use crate::email::EmailUpdate;
use crate::env::ConfigurationKey::{
    EmailAccountCreatedTemplate, EmailAccountCreatedTitle, EmailOneTimeLoginTemplate,
    EmailOneTimeLoginTitle, EmailVerifyEmailTemplate, EmailVerifyEmailTitle,
};
use crate::env::secret_value;
use crate::norm::normalize_email;
use crate::prefix::USER_PATH_PREFIX;
use crate::store::Snapshot;
use crate::user::{Email, IdentificationMethod, User};
use http_body_util::{Either, Empty, Full};
use hyper::body::Bytes;
use hyper::header::{HeaderValue, LOCATION, SET_COOKIE};
use hyper::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, LazyLock};

//noinspection SpellCheckingInspection
static EMAIL_ONE_TIME_LOGIN_TITLE: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailOneTimeLoginTitle));
//noinspection SpellCheckingInspection
static EMAIL_ONE_TIME_LOGIN_TEMPLATE: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailOneTimeLoginTemplate));

//noinspection SpellCheckingInspection
static EMAIL_ACCOUNT_CREATED_TITLE: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailAccountCreatedTitle));
//noinspection SpellCheckingInspection
static EMAIL_ACCOUNT_CREATED_TEMPLATE: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailAccountCreatedTemplate));

//noinspection SpellCheckingInspection
static EMAIL_ACCOUNT_VERIFY_EMAIL_TITLE: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailVerifyEmailTitle));
//noinspection SpellCheckingInspection
static EMAIL_ACCOUNT_VERIFIY_EMAIL_TEMPLATE: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailVerifyEmailTemplate));

#[derive(Copy, Clone, Serialize, Deserialize)]
pub enum Event {
    #[serde(rename = "first_login")]
    FirstLogin,
    #[serde(rename = "login")]
    Login,
    #[serde(rename = "email_update")]
    EmailUpdate,
}

impl Event {
    pub(crate) fn otp_validity_duration(&self) -> Option<u32> {
        match self {
            Event::FirstLogin => None,
            Event::Login => {
                Some(1_200) // 20 mins
            }
            Event::EmailUpdate => {
                Some(1_200) // 20 mins
            }
        }
    }
    pub(crate) fn email_template(&self) -> (Option<&'static str>, Option<&'static str>) {
        match self {
            Event::FirstLogin => (
                *EMAIL_ACCOUNT_CREATED_TITLE,
                *EMAIL_ACCOUNT_CREATED_TEMPLATE,
            ),
            Event::Login => (*EMAIL_ONE_TIME_LOGIN_TITLE, *EMAIL_ONE_TIME_LOGIN_TEMPLATE),
            Event::EmailUpdate => (
                *EMAIL_ACCOUNT_VERIFY_EMAIL_TITLE,
                *EMAIL_ACCOUNT_VERIFIY_EMAIL_TEMPLATE,
            ),
        }
    }
    pub(crate) async fn execute(
        self,
        mut user: User,
        value: Option<Value>,
        snapshot: &Arc<Snapshot>,
    ) -> Option<Response<Either<Full<Bytes>, Empty<Bytes>>>> {
        match self {
            Event::FirstLogin | Event::Login => {
                let session = User::create_session(&user.id, snapshot, None).await?;
                let mut response = Response::builder();
                let headers = response.headers_mut().unwrap();
                session.cookies(true).into_iter().for_each(|cookie| {
                    headers.append(SET_COOKIE, cookie);
                });
                headers.insert(
                    LOCATION,
                    HeaderValue::from_static(USER_PATH_PREFIX.without_trailing_slash),
                );
                Some(
                    response
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .body(Either::Right(Empty::new()))
                        .unwrap(),
                )
            }
            Event::EmailUpdate => {
                let email_update = value
                    .as_ref()
                    .and_then(|it| EmailUpdate::deserialize(it).ok())?;
                let mut found = false;
                for it in user.identification.iter_mut() {
                    if let IdentificationMethod::Email(Email {
                        normalized_address,
                        address,
                    }) = it
                    {
                        if email_update.old_email == normalized_address {
                            *normalized_address = normalize_email(email_update.new_email);
                            *address = email_update.new_email.to_string();
                            found = true;
                            break;
                        }
                    }
                }
                Snapshot::set_and_wait_for_update(&format!("acc/{}", user.id), &user).await?;
                let mut response = Response::builder();
                let headers = response.headers_mut().unwrap();
                headers.insert(
                    LOCATION,
                    HeaderValue::from_static(USER_PATH_PREFIX.without_trailing_slash),
                );
                Some(
                    response
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .body(Either::Right(Empty::new()))
                        .unwrap(),
                )
            }
        }
    }
}
