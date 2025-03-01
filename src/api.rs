use crate::otp::handle_otp;
use crate::store::Snapshot;
use crate::verify::handle_verify;
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use pinboard::NonEmptyPinboard;
use std::sync::Arc;

pub(crate) async fn handle_api(
    request: Request<Incoming>,
    store_cache: Arc<NonEmptyPinboard<Snapshot>>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = &request.uri().path()[4..];
    if path.starts_with("/otp/") {
        return handle_otp(request).await;
    } else if path.starts_with("/verify/") {
        return handle_verify(request).await;
    } else if path == "/auth/req" {
        todo!("passkey sign-in request")
    }
    Response::new(Either::Right(Empty::new()))
}
