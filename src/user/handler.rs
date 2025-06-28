use crate::headers::{GET, GET_POST, POST};
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

pub(crate) enum RequestOrResponse {
    Req(Request<Incoming>),
    Res(Response<Either<Full<Bytes>, Empty<Bytes>>>),
}

#[allow(clippy::inconsistent_digit_grouping)]
pub(crate) async fn handle_user(
    request: Request<Incoming>,
    server_name: &Arc<String>,
) -> RequestOrResponse {
    let path = request
        .uri()
        .path()
        .strip_prefix(API_PATH_PREFIX.without_trailing_slash)
        .unwrap()
        .strip_prefix("/user")
        .unwrap();
    if path == "/" || path.is_empty() {
        return if request.method() == Method::POST {
            RequestOrResponse::Res(endpoints::root::post(request, server_name).await)
        } else if request.method() == Method::GET {
            RequestOrResponse::Res(endpoints::root::get(request, server_name).await)
        } else {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, GET_POST);
            info!("405 {}/user", API_PATH_PREFIX.without_trailing_slash);
            RequestOrResponse::Res(
                response
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Either::Right(Empty::new()))
                    .unwrap(),
            )
        };
    } else if path == "/email" {
        return RequestOrResponse::Res(if request.method() != Method::POST {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, POST);
            info!("405 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
            response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap()
        } else {
            endpoints::email::post(request, server_name).await
        });
    } else if let Some(path) = path.strip_prefix("/admin") {
        let snapshot = snapshot();
        if SessionState::from_headers(request.headers(), &snapshot)
            .await
            .is_admin()
        {
            if path == "/registrations/code" {
                return RequestOrResponse::Res(if request.method() != Method::GET {
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
                });
            } else if path == "/users" {
                return RequestOrResponse::Res(if request.method() != Method::GET {
                    let mut response = Response::builder();
                    let headers = response.headers_mut().unwrap();
                    headers.insert(ALLOW, GET);
                    info!("405 https://{server_name}/api/user/admin/users");
                    response
                        .status(StatusCode::METHOD_NOT_ALLOWED)
                        .body(Either::Right(Empty::new()))
                        .unwrap()
                } else {
                    endpoints::admin::users::get(&snapshot).await
                });
            } else if path == "/registrations" {
                return RequestOrResponse::Res(if request.method() == Method::GET {
                    endpoints::admin::registrations::get(&snapshot).await
                } else if request.method() == Method::POST {
                    endpoints::admin::registrations::post(request, server_name, &snapshot).await
                } else {
                    let mut response = Response::builder();
                    let headers = response.headers_mut().unwrap();
                    headers.insert(ALLOW, GET_POST);
                    info!("405 https://{server_name}/api/user/admin/registrations");
                    return RequestOrResponse::Res(
                        response
                            .status(StatusCode::METHOD_NOT_ALLOWED)
                            .body(Either::Right(Empty::new()))
                            .unwrap(),
                    );
                });
            }
        } else {
            info!("403 https://{server_name}/api/user/admin{path}");
            return RequestOrResponse::Res(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Either::Right(Empty::new()))
                    .unwrap(),
            );
        }
    }
    RequestOrResponse::Req(request)
}
