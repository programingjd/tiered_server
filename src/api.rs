use crate::auth::handle_auth;
use crate::otp::{Action, handle_otp};
use crate::user::{RequestOrResponse, User, handle_user};
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use serde_json::Value;
use std::sync::Arc;

pub trait Extension {
    fn handle_api_extension(
        &self,
        request: Request<Incoming>,
        server_name: &Arc<String>,
    ) -> impl Future<Output = Option<Response<Either<Full<Bytes>, Empty<Bytes>>>>> + Send;
    fn perform_action(
        &self,
        user: &User,
        action: Action,
        value: Option<&Value>,
    ) -> impl Future<Output = Option<()>> + Send;
}

pub(crate) async fn handle_api<Ext: Extension + Send + Sync>(
    request: Request<Incoming>,
    server_name: &Arc<String>,
    extension: &Ext,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = &request.uri().path()[4..];
    if path == "/auth" || path.starts_with("/auth/") {
        handle_auth(request, server_name).await
    } else if path == "/otp" || path.starts_with("/otp/") {
        handle_otp(request, server_name, extension).await
    } else if path == "/user" || path.starts_with("/user/") {
        match handle_user(request, server_name).await {
            RequestOrResponse::Res(response) => response,
            RequestOrResponse::Req(request) => {
                if let Some(response) = extension.handle_api_extension(request, server_name).await {
                    response
                } else {
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Either::Right(Empty::new()))
                        .unwrap()
                }
            }
        }
    } else if let Some(response) = extension.handle_api_extension(request, server_name).await {
        response
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Either::Right(Empty::new()))
            .unwrap()
    }
}
