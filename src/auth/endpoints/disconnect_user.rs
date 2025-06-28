use crate::prefix::API_PATH_PREFIX;
use crate::session::{SID_EXPIRED, Session};
use crate::store::Snapshot;
use http_body_util::{Either, Empty, Full};
use hyper::body::Bytes;
use hyper::header::{HeaderValue, LOCATION, SET_COOKIE};
use hyper::{Response, StatusCode};
use tracing::info;

pub(crate) async fn get(
    session: Option<Session>,
) -> Option<Response<Either<Full<Bytes>, Empty<Bytes>>>> {
    if let Some(mut session) = session {
        session.timestamp = 0;
        Snapshot::set_and_wait_for_update(&format!("sid/{}", session.id), &session).await;
    }
    info!(
        "302 {}/auth/disconnect_user",
        API_PATH_PREFIX.without_trailing_slash
    );
    let mut response = Response::builder().status(StatusCode::FOUND);
    let headers = response.headers_mut().unwrap();
    headers.insert(LOCATION, HeaderValue::from_static("/"));
    headers.append(SET_COOKIE, SID_EXPIRED);
    Some(response.body(Either::Right(Empty::new())).unwrap())
}
