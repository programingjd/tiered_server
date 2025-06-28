use crate::prefix::API_PATH_PREFIX;
use crate::session::{DELETE_SID_COOKIES, DELETE_ST_COOKIES, Session};
use crate::store::Snapshot;
use http_body_util::{Either, Empty, Full};
use hyper::body::Bytes;
use hyper::header::SET_COOKIE;
use hyper::{Response, StatusCode};
use tracing::info;

pub(crate) async fn get(
    session: Option<Session>,
) -> Option<Response<Either<Full<Bytes>, Empty<Bytes>>>> {
    if let Some(session) = session {
        Snapshot::delete([format!("sid/{}", session.id)].iter()).await;
    }
    info!(
        "200 {}/auth/forget_user",
        API_PATH_PREFIX.without_trailing_slash
    );
    let mut response = Response::builder().status(StatusCode::OK);
    let headers = response.headers_mut().unwrap();
    headers.append(SET_COOKIE, DELETE_ST_COOKIES);
    headers.append(SET_COOKIE, DELETE_SID_COOKIES);
    Some(response.body(Either::Right(Empty::new())).unwrap())
}
