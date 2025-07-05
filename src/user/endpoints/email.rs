use crate::email::EmailUpdate;
use crate::otp::Otp;
use crate::otp::action::Event;
use crate::prefix::API_PATH_PREFIX;
use crate::session::SessionState;
use crate::store::snapshot;
use crate::user::{Email, IdentificationMethod};
use http_body_util::{BodyExt, Either, Empty, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use serde_json::json;
use std::sync::Arc;
use tracing::info;

fn dummy_error() -> Box<dyn std::error::Error + Send + Sync> {
    Box::from("")
}

pub(crate) async fn post(
    request: Request<Incoming>,
    server_name: &Arc<String>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let snapshot = snapshot();
    if let SessionState::Valid { user, .. } =
        SessionState::from_headers(request.headers(), &snapshot)
    {
        let limited_body = Limited::new(request.into_body(), 4_096);
        match limited_body.collect().await.and_then(|it| {
            let bytes = it.to_bytes();
            let EmailUpdate {
                old_email,
                new_email,
            } = serde_json::from_slice(&bytes).map_err(|_| dummy_error())?;
            user.identification
                .iter()
                .find(|&it| match it {
                    IdentificationMethod::Email(Email {
                        normalized_address, ..
                    }) => &old_email == normalized_address,
                    _ => false,
                })
                .ok_or_else(dummy_error)?;
            let len = new_email.len();
            if new_email.is_ascii() && len > 5 && new_email[1..len - 4].contains('@') {
                Ok((
                    json!({
                        "old_email": old_email,
                        "new_email": new_email,
                    }),
                    new_email.to_string(),
                ))
            } else {
                Err(dummy_error())
            }
        }) {
            Ok((value, email)) => {
                if Otp::send_with_email(
                    &user,
                    email.as_str(),
                    Event::EmailUpdate,
                    Some(value),
                    &snapshot,
                    server_name,
                )
                .await
                .is_some()
                {
                    info!("202 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
                    Response::builder()
                        .status(StatusCode::ACCEPTED)
                        .body(Either::Right(Empty::new()))
                        .unwrap()
                } else {
                    info!("500 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Either::Right(Empty::new()))
                        .unwrap()
                }
            }
            Err(err) => {
                if let Some(limited_error) = err.downcast_ref::<serde_json::Error>() {
                    info!("413 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
                    Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Either::Right(Empty::new()))
                        .unwrap()
                } else {
                    info!("400 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Either::Right(Empty::new()))
                        .unwrap()
                }
            }
        }
    } else {
        info!("403 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Either::Right(Empty::new()))
            .unwrap()
    }
}
