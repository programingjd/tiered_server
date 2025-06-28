use crate::headers::TEXT;
use crate::prefix::API_PATH_PREFIX;
use crate::user::VALIDATION_TOTP_SECRET;
use http_body_util::{Either, Empty, Full};
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::{Response, StatusCode};
use tracing::info;

pub(crate) async fn get() -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    if let Some(secret) = *VALIDATION_TOTP_SECRET {
        info!(
            "200 {}/user/admin/reg/code",
            API_PATH_PREFIX.without_trailing_slash
        );
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, TEXT)
            .body(Either::Left(Full::from(secret)))
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Either::Right(Empty::new()))
            .unwrap()
    }
}
