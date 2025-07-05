use crate::headers::JSON;
use crate::store::Snapshot;
use crate::user::{IdentificationMethod, User};
use http_body_util::{Either, Empty, Full};
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::{Response, StatusCode};
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

pub(crate) mod login_as;
pub(crate) mod registration_code;
pub(crate) mod registrations;
pub(crate) mod users;

#[derive(Serialize)]
struct UserResponse {
    first_name: String,
    last_name: String,
    date_of_birth: u32,
    emails: Vec<String>,
    sms_numbers: Vec<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
}

#[derive(Copy, Clone)]
pub(crate) enum UserOrRegistration {
    User,
    Registration,
}

impl UserOrRegistration {
    fn as_key(self) -> &'static str {
        match self {
            UserOrRegistration::User => "acc/",
            UserOrRegistration::Registration => "reg/",
        }
    }
}

pub(crate) async fn list(
    snapshot: &Arc<Snapshot>,
    user_or_registration: UserOrRegistration,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let list = snapshot
        .list::<User>(user_or_registration.as_key())
        .map(|(_, user)| {
            let mut emails = Vec::with_capacity(1);
            let mut sms_numbers = Vec::with_capacity(0);
            for it in user.identification.into_iter() {
                match it {
                    IdentificationMethod::Email(email) => emails.push(email.normalized_address),
                    IdentificationMethod::Sms(sms) => sms_numbers.push(sms.normalized_number),
                    _ => {}
                };
            }
            UserResponse {
                first_name: user.first_name,
                last_name: user.last_name,
                date_of_birth: user.date_of_birth,
                emails,
                sms_numbers,
                metadata: user.metadata,
            }
        })
        .collect::<Vec<_>>();
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, JSON)
        .body(Either::Left(Full::from(serde_json::to_vec(&list).unwrap())))
        .unwrap()
}
