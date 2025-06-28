use crate::auth::endpoints;
use crate::headers::{GET, HEAD, POST};
use crate::prefix::API_PATH_PREFIX;
use crate::session::SessionState;
use crate::store::snapshot;
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::ALLOW;
use hyper::{Method, Request, Response, StatusCode};
use std::sync::Arc;
use tracing::info;

//noinspection DuplicatedCode
pub(crate) async fn handle_auth(
    request: Request<Incoming>,
    server_name: &Arc<String>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = request
        .uri()
        .path()
        .strip_prefix(API_PATH_PREFIX.without_trailing_slash)
        .unwrap()
        .strip_prefix("/auth")
        .unwrap();
    let method = request.method();
    let snapshot = snapshot();
    let session_state = SessionState::from_headers(request.headers(), &snapshot).await;
    let (user, session) = match session_state {
        SessionState::Valid { user, session } => (Some(user), Some(session)),
        SessionState::Expired { user } => (Some(user), None),
        _ => (None, None),
    };
    if path == "/credential_request_options" {
        if method != Method::POST {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, POST);
            info!(
                "405 {}/auth/credential_request_options",
                API_PATH_PREFIX.without_trailing_slash
            );
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        if let Some(response) = endpoints::credential_request_options::post(request).await {
            return response;
        }
    } else if path == "/credentials" {
        if let Some(user) = user {
            if method != Method::HEAD {
                let mut response = Response::builder();
                let headers = response.headers_mut().unwrap();
                headers.insert(ALLOW, HEAD);
                info!(
                    "405 {}/auth/credentials",
                    API_PATH_PREFIX.without_trailing_slash
                );
                return response
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Either::Right(Empty::new()))
                    .unwrap();
            }
            if let Some(response) = endpoints::credentials::head(&snapshot, user) {
                return response;
            }
        }
        info!(
            "403 {}/auth/credentials",
            API_PATH_PREFIX.without_trailing_slash
        );
    } else if path == "/credential_creation_options" {
        if session.is_none() {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        if method != Method::POST {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, POST);
            info!(
                "405 {}/auth/credential_creation_options",
                API_PATH_PREFIX.without_trailing_slash
            );
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        let user = user.unwrap();
        if let Some(response) =
            endpoints::credential_creation_options::post(request, &snapshot, user).await
        {
            return response;
        }
        info!(
            "403 {}/auth/credential_creation_options",
            API_PATH_PREFIX.without_trailing_slash
        );
    } else if path == "/record_credential" {
        if session.is_none() {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        if request.method() != Method::POST {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, POST);
            info!(
                "405 {}/auth/record_credential",
                API_PATH_PREFIX.without_trailing_slash
            );
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        let user = user.unwrap();
        if let Some(response) = endpoints::record_credential::post(request, &snapshot, user).await {
            return response;
        }
        info!(
            "403 {}/auth/record_credential",
            API_PATH_PREFIX.without_trailing_slash
        );
    } else if path == "/validate_credential" {
        if request.method() != Method::POST {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, POST);
            info!(
                "405 {}/auth/validate_credential",
                API_PATH_PREFIX.without_trailing_slash
            );
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        if let Some(response) =
            endpoints::validate_credential::post(request, server_name, &snapshot).await
        {
            return response;
        }
        info!(
            "403 {}/auth/validate_credential",
            API_PATH_PREFIX.without_trailing_slash
        );
    } else if path == "/forget_user" {
        if request.method() != Method::GET {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, GET);
            info!(
                "405 {}/auth/forget_user",
                API_PATH_PREFIX.without_trailing_slash
            );
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        if user.is_some() {
            if let Some(response) = endpoints::forget_user::get(session).await {
                return response;
            }
        }
        info!(
            "403 {}/auth/forget_user",
            API_PATH_PREFIX.without_trailing_slash
        );
    } else if path == "/disconnect_user" {
        if request.method() != Method::GET {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, GET);
            info!(
                "405 {}/auth/disconnect_user",
                API_PATH_PREFIX.without_trailing_slash
            );
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        if user.is_some() {
            if let Some(response) = endpoints::disconnect_user::get(session).await {
                return response;
            }
        }
        info!(
            "403 {}/auth/disconnect_user",
            API_PATH_PREFIX.without_trailing_slash
        );
    }
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Either::Right(Empty::new()))
        .unwrap()
}
