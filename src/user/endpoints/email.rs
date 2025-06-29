use crate::otp::Otp;
use crate::otp::action::Action;
use crate::prefix::API_PATH_PREFIX;
use crate::session::SessionState;
use crate::store::snapshot;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use serde_json::json;
use std::sync::Arc;
use tracing::info;

pub(crate) async fn post(
    request: Request<Incoming>,
    server_name: &Arc<String>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let snapshot = snapshot();
    if let SessionState::Valid { user, .. } =
        SessionState::from_headers(request.headers(), &snapshot)
    {
        if let Some(value) = request.into_body().collect().await.ok().and_then(|it| {
            let bytes = it.to_bytes();
            if bytes.is_ascii() {
                let email = String::from_utf8_lossy(&bytes);
                let len = email.len();
                if len > 5 && email[1..len - 4].contains('@') {
                    return Some(json!({
                        "new_email": email.as_ref()
                    }));
                }
            }
            None
        }) {
            if Otp::send(
                &user,
                Action::EmailUpdate,
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
        } else {
            info!("400 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Either::Right(Empty::new()))
                .unwrap()
        }
    } else {
        info!("403 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Either::Right(Empty::new()))
            .unwrap()
    }
}
