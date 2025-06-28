use crate::api::Extension;
use crate::headers::{GET, POST};
use crate::otp::endpoints;
use crate::prefix::API_PATH_PREFIX;
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::ALLOW;
use hyper::{Method, Request, Response, StatusCode};
use std::sync::Arc;
use tracing::info;

pub(crate) async fn handle_otp<Ext: Extension + Send + Sync>(
    request: Request<Incoming>,
    server_name: &Arc<String>,
    extension: &Ext,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = request
        .uri()
        .path()
        .strip_prefix(API_PATH_PREFIX.without_trailing_slash)
        .unwrap()
        .strip_prefix("/otp")
        .unwrap();
    if path == "/" || path.is_empty() {
        if request.method() != Method::POST {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, POST);
            info!("405 {}/otp{path}", API_PATH_PREFIX.without_trailing_slash);
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        endpoints::root::post(request, server_name).await
    } else if request.method() != Method::GET {
        let mut response = Response::builder();
        let headers = response.headers_mut().unwrap();
        headers.insert(ALLOW, GET);
        info!("405 {}/otp{path}", API_PATH_PREFIX.without_trailing_slash);
        response
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Either::Right(Empty::new()))
            .unwrap()
    } else {
        endpoints::root::get(request, extension).await
    }
}
