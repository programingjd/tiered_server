use crate::auth::passkey::PassKey;
use crate::browser::Platform;
use crate::headers::JSON;
use crate::prefix::API_PATH_PREFIX;
use crate::session::SessionState;
use crate::store::{Snapshot, snapshot};
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::{Request, Response, StatusCode};
use serde::Serialize;
use std::borrow::Cow;
use tracing::info;

#[derive(Serialize)]
struct PasskeyMetadata {
    id: String,
    platform: Platform,
    brand: Cow<'static, str>,
}

impl From<PassKey> for PasskeyMetadata {
    fn from(value: PassKey) -> Self {
        Self {
            id: value.id,
            platform: value.browser_info.platform,
            brand: value.browser_info.brand,
        }
    }
}

pub(crate) async fn get(request: Request<Incoming>) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let snapshot = snapshot();
    if let SessionState::Valid { user, .. } =
        SessionState::from_headers(request.headers(), &snapshot)
    {
        let keys = snapshot
            .list::<PassKey>(&format!("pk/{}/", user.id))
            .map(|(_, v)| v.into())
            .collect::<Vec<PasskeyMetadata>>();
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, JSON)
            .body(Either::Left(Full::from(serde_json::to_vec(&keys).unwrap())))
            .unwrap()
    } else {
        info!(
            "403 {}/user/passkeys",
            API_PATH_PREFIX.without_trailing_slash
        );
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Either::Right(Empty::new()))
            .unwrap()
    }
}

pub(crate) async fn delete(
    request: Request<Incoming>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let snapshot = snapshot();
    let id = request
        .uri()
        .path()
        .strip_prefix(API_PATH_PREFIX.without_trailing_slash)
        .unwrap()
        .strip_prefix("/user/passkeys/")
        .unwrap();
    if let SessionState::Valid { user, .. } =
        SessionState::from_headers(request.headers(), &snapshot)
    {
        if URL_SAFE_NO_PAD.decode_to_vec(id).is_err() {
            info!(
                "400 {}/user/passkeys/{id}",
                API_PATH_PREFIX.without_trailing_slash
            );
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Either::Right(Empty::new()))
                .unwrap()
        } else if Snapshot::delete([format!("pk/{}/{id}", user.id)].iter())
            .await
            .is_some()
        {
            info!(
                "204 {}/user/passkeys/{id}",
                API_PATH_PREFIX.without_trailing_slash
            );
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Either::Right(Empty::new()))
                .unwrap()
        } else {
            info!(
                "500 {}/user/passkeys/{id}",
                API_PATH_PREFIX.without_trailing_slash
            );
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Either::Right(Empty::new()))
                .unwrap()
        }
    } else {
        info!(
            "403 {}/user/passkeys/{id}",
            API_PATH_PREFIX.without_trailing_slash
        );
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Either::Right(Empty::new()))
            .unwrap()
    }
}
