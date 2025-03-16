use crate::auth::handle_auth;
use crate::otp::handle_otp;
use crate::reg::handle_reg;
use crate::store::Snapshot;
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
    if path.starts_with("/auth/") {
        return handle_auth(request, store_cache).await;
    } else if path.starts_with("/otp/") {
        return handle_otp(request, store_cache).await;
    } else if path.starts_with("/reg/") {
        return handle_reg(request, store_cache).await;
    }
    Response::new(Either::Right(Empty::new()))
}
