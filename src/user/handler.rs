use crate::api::{Extension, handle_api_extension};
use crate::headers::{DELETE, GET, GET_POST, POST};
use crate::prefix::API_PATH_PREFIX;
use crate::session::SessionState;
use crate::store::snapshot;
use crate::user::endpoints;
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::ALLOW;
use hyper::{Method, Request, Response, StatusCode};
use std::sync::Arc;
use tracing::info;

pub(crate) async fn handle_user<Ext: Extension + Send + Sync>(
    request: Request<Incoming>,
    server_name: &Arc<String>,
    extension: &Ext,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = request
        .uri()
        .path()
        .strip_prefix(API_PATH_PREFIX.without_trailing_slash)
        .unwrap()
        .strip_prefix("/user")
        .unwrap();
    if path == "/" || path.is_empty() {
        if request.method() == Method::POST {
            endpoints::root::post(request, server_name, extension).await
        } else if request.method() == Method::GET {
            endpoints::root::get(request).await
        } else {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, GET_POST);
            info!("405 {}/user", API_PATH_PREFIX.without_trailing_slash);
            response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap()
        }
    } else if path == "/passkeys" {
        if request.method() != Method::GET {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, GET);
            info!(
                "405 {}/user/passkeys",
                API_PATH_PREFIX.without_trailing_slash
            );
            response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap()
        } else {
            endpoints::passkeys::get(request).await
        }
    } else if path.starts_with("/passkeys/") {
        if request.method() != Method::DELETE {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, DELETE);
            info!("405 {}/user{path}", API_PATH_PREFIX.without_trailing_slash);
            response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap()
        } else {
            endpoints::passkeys::delete(request).await
        }
    } else if path == "/email" {
        if request.method() != Method::POST {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, POST);
            info!("405 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
            response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap()
        } else {
            endpoints::email::post(request, extension).await
        }
    } else if let Some(path) = path.strip_prefix("/admin") {
        let snapshot = snapshot();
        let admin_session = match SessionState::from_headers(request.headers(), &snapshot) {
            SessionState::Valid { user, session } if user.admin => Some(session),
            _ => None,
        };
        if let Some(session) = admin_session {
            if path == "/registrations/code" {
                if request.method() != Method::GET {
                    let mut response = Response::builder();
                    let headers = response.headers_mut().unwrap();
                    headers.insert(ALLOW, GET);
                    info!(
                        "405 {}/user/admin/registrations/code",
                        API_PATH_PREFIX.without_trailing_slash
                    );
                    response
                        .status(StatusCode::METHOD_NOT_ALLOWED)
                        .body(Either::Right(Empty::new()))
                        .unwrap()
                } else {
                    endpoints::admin::registration_code::get().await
                }
            } else if path == "/users" {
                if request.method() != Method::GET {
                    let mut response = Response::builder();
                    let headers = response.headers_mut().unwrap();
                    headers.insert(ALLOW, GET);
                    info!(
                        "405 {}/user/admin/users",
                        API_PATH_PREFIX.without_trailing_slash
                    );
                    response
                        .status(StatusCode::METHOD_NOT_ALLOWED)
                        .body(Either::Right(Empty::new()))
                        .unwrap()
                } else {
                    endpoints::admin::users::get(&snapshot).await
                }
            } else if path == "/registrations" {
                if request.method() == Method::GET {
                    endpoints::admin::registrations::get(&snapshot).await
                } else if request.method() == Method::POST {
                    endpoints::admin::registrations::post(request, server_name, &snapshot).await
                } else {
                    let mut response = Response::builder();
                    let headers = response.headers_mut().unwrap();
                    headers.insert(ALLOW, GET_POST);
                    info!(
                        "405 {}/user/admin/registrations",
                        API_PATH_PREFIX.without_trailing_slash
                    );
                    response
                        .status(StatusCode::METHOD_NOT_ALLOWED)
                        .body(Either::Right(Empty::new()))
                        .unwrap()
                }
            } else if path == "/login_as" {
                if request.method() == Method::POST {
                    endpoints::admin::login_as::post(request, session, &snapshot).await
                } else {
                    let mut response = Response::builder();
                    let headers = response.headers_mut().unwrap();
                    headers.insert(ALLOW, POST);
                    info!(
                        "405 {}/user/admin/login_as",
                        API_PATH_PREFIX.without_trailing_slash
                    );
                    response
                        .status(StatusCode::METHOD_NOT_ALLOWED)
                        .body(Either::Right(Empty::new()))
                        .unwrap()
                }
            } else {
                handle_api_extension(request, server_name, extension).await
            }
        } else {
            info!(
                "403 {}/user/admin{path}",
                API_PATH_PREFIX.without_trailing_slash
            );
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Either::Right(Empty::new()))
                .unwrap()
        }
    } else {
        handle_api_extension(request, server_name, extension).await
    }
}
