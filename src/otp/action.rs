use crate::env::ConfigurationKey::{
    EmailAccountCreatedTemplate, EmailAccountCreatedTitle, EmailOneTimeLoginTemplate,
    EmailOneTimeLoginTitle, EmailVerifyEmailTemplate, EmailVerifyEmailTitle,
};
use crate::env::secret_value;
use crate::prefix::USER_PATH_PREFIX;
use crate::store::Snapshot;
use crate::user::{IdentificationMethod, User};
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
pub enum Action {
    #[serde(rename = "first_login")]
    FirstLogin,
    #[serde(rename = "login")]
    Login,
    #[serde(rename = "email_update")]
    EmailUpdate,
}

impl Action {
    pub(crate) fn otp_validity_duration(&self) -> Option<u32> {
        match self {
            Action::FirstLogin => None,
            Action::Login => {
                Some(1_200) // 20 mins
            }
            Action::EmailUpdate => {
                Some(1_200) // 20 mins
            }
        }
    }
    pub(crate) fn email_template(&self) -> (Option<&'static str>, Option<&'static str>) {
        match self {
            Action::FirstLogin => (
                *EMAIL_ACCOUNT_CREATED_TITLE,
                *EMAIL_ACCOUNT_CREATED_TEMPLATE,
            ),
            Action::Login => (*EMAIL_ONE_TIME_LOGIN_TITLE, *EMAIL_ONE_TIME_LOGIN_TEMPLATE),
            Action::EmailUpdate => (
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
            Action::FirstLogin | Action::Login => {
                let session = User::create_session(&user.id, snapshot, None).await?;
                let mut response = Response::builder();
                let headers = response.headers_mut().unwrap();
                session.cookies().into_iter().for_each(|cookie| {
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
            Action::EmailUpdate => {
                let email = value.and_then(|it| serde_json::from_value::<String>(it).ok())?;
                user.identification = IdentificationMethod::Email(email.into());
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
