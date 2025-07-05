use crate::prefix::API_PATH_PREFIX;
use crate::session::{DELETE_SID_COOKIES, DELETE_ST_COOKIES, SID_EXPIRED, Session};
use crate::store::Snapshot;
use http_body_util::{Either, Empty, Full};
use hyper::body::Bytes;
use hyper::header::{HeaderValue, LOCATION, SET_COOKIE};
use hyper::{Response, StatusCode};
use tracing::info;

pub(crate) async fn get(
    session: Option<Session>,
) -> Option<Response<Either<Full<Bytes>, Empty<Bytes>>>> {
    let mut response = Response::builder().status(StatusCode::FOUND);
    let headers = response.headers_mut().unwrap();
    headers.insert(LOCATION, HeaderValue::from_static("/"));
    if let Some(mut session) = session {
        if session.delegated {
            Snapshot::delete_and_wait_for_update([format!("sid/{}", session.id)].iter()).await;
            headers.append(SET_COOKIE, SID_EXPIRED);
        } else {
            session.timestamp = 0;
            Snapshot::set_and_wait_for_update(&format!("sid/{}", session.id), &session).await;
            headers.append(SET_COOKIE, DELETE_ST_COOKIES);
            headers.append(SET_COOKIE, DELETE_SID_COOKIES);
        }
    }
    info!(
        "302 {}/auth/disconnect_user",
        API_PATH_PREFIX.without_trailing_slash
    );
    Some(response.body(Either::Right(Empty::new())).unwrap())
}
