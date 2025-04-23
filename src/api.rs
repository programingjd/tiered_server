use crate::auth::handle_auth;
use crate::otp::handle_otp;
use crate::store::Snapshot;
use crate::user::handle_user;
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use pinboard::NonEmptyPinboard;
use std::sync::Arc;
use zip_static_handler::handler::Handler;

pub trait Extension {
    fn handle_api_extension(
        &self,
        request: Request<Incoming>,
        store_cache: &Arc<NonEmptyPinboard<Snapshot>>,
        handler: Arc<Handler>,
        server_name: Arc<String>,
    ) -> impl Future<Output = Option<Response<Either<Full<Bytes>, Empty<Bytes>>>>> + Send;
}

pub(crate) async fn handle_api<Ext: Extension + Send + Sync>(
    request: Request<Incoming>,
    store_cache: &Arc<NonEmptyPinboard<Snapshot>>,
    handler: Arc<Handler>,
    server_name: Arc<String>,
    extension: &Ext,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = &request.uri().path()[4..];
    if path == "/auth" || path.starts_with("/auth/") {
        return handle_auth(request, store_cache, server_name).await;
    } else if path == "/otp" || path.starts_with("/otp/") {
        return handle_otp(request, store_cache, handler, server_name).await;
    } else if path == "/user" || path.starts_with("/user/") {
        return handle_user(request, store_cache, server_name).await;
    }
    if let Some(response) = extension
        .handle_api_extension(request, store_cache, handler, server_name)
        .await
    {
        return response;
    }
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Either::Right(Empty::new()))
        .unwrap()
}
