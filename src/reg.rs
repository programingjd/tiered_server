use crate::env::ConfigurationKey::ValidationTotpSecret;
use crate::env::secret_value;
use crate::session::SessionState;
use crate::store::Snapshot;
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::http::HeaderValue;
use hyper::{Request, Response, StatusCode};
use pinboard::NonEmptyPinboard;
use std::sync::{Arc, LazyLock};

const TEXT: HeaderValue = HeaderValue::from_static("text/plain");

//noinspection SpellCheckingInspection
static VALIDATION_TOTP_SECRET: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(ValidationTotpSecret));

pub(crate) async fn handle_reg(
    request: Request<Incoming>,
    store_cache: Arc<NonEmptyPinboard<Snapshot>>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = &request.uri().path()[8..];
    if let SessionState::Valid { user } =
        SessionState::from_headers(request.headers(), &store_cache).await
    {
        if path == "/code" {
            if user.admin {
                if let Some(secret) = *VALIDATION_TOTP_SECRET {
                    return Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, TEXT)
                        .body(Either::Left(Full::from(secret)))
                        .unwrap();
                }
            }
        }
    }
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Either::Right(Empty::new()))
        .unwrap()
}
