use crate::env::ConfigurationKey::{
    EmailAccountCreatedTemplate, EmailAccountCreatedTitle, EmailOneTimeLoginTemplate,
    EmailOneTimeLoginTitle,
};
use crate::env::secret_value;
use crate::prefix::USER_PATH_PREFIX;
use crate::store::Snapshot;
use crate::user::User;
use http_body_util::{Either, Empty, Full};
use hyper::body::Bytes;
use hyper::header::{HeaderValue, LOCATION, SET_COOKIE};
use hyper::{Response, StatusCode};
use serde::{Deserialize, Serialize};
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

#[derive(Copy, Clone, Serialize, Deserialize)]
pub enum Action {
    #[serde(rename = "first_login")]
    FirstLogin,
    #[serde(rename = "login")]
    Login,
}

impl Action {
    pub(crate) fn validity_duration(&self) -> Option<u32> {
        match self {
            Self::FirstLogin => None,
            Self::Login => Some(1_200), // 20 mins
        }
    }
    pub(crate) fn email_template(&self) -> (Option<&'static str>, Option<&'static str>) {
        match self {
            Action::FirstLogin => (
                *EMAIL_ACCOUNT_CREATED_TITLE,
                *EMAIL_ACCOUNT_CREATED_TEMPLATE,
            ),
            Action::Login => (*EMAIL_ONE_TIME_LOGIN_TITLE, *EMAIL_ONE_TIME_LOGIN_TEMPLATE),
        }
    }
    pub(crate) async fn handle(
        self,
        user: User,
        snapshot: &Arc<Snapshot>,
    ) -> Option<Response<Either<Full<Bytes>, Empty<Bytes>>>> {
        match self {
            Action::FirstLogin | Action::Login => {
                let session = User::create_session(&user, snapshot, None, false).await?;
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
        }
    }
}
