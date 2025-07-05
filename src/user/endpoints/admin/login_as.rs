use crate::iter::single;
use crate::prefix::{API_PATH_PREFIX, USER_PATH_PREFIX};
use crate::session::Session;
use crate::store::Snapshot;
use http_body_util::{BodyExt, Either, Empty, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, LOCATION, SET_COOKIE};
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use tracing::info;

fn dummy_error() -> Box<dyn std::error::Error + Send + Sync> {
    Box::from("")
}

#[derive(serde::Deserialize)]
struct User<'a> {
    #[serde(borrow)]
    first_name: &'a str,
    #[serde(borrow)]
    last_name: &'a str,
    date_of_birth: u32,
}

pub(crate) async fn post(
    request: Request<Incoming>,
    session: Session,
    snapshot: &Arc<Snapshot>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let limited_body = Limited::new(request.into_body(), 4_096);
    match limited_body.collect().await.and_then(|it| {
        let bytes = it.to_bytes();
        let User {
            first_name,
            last_name,
            date_of_birth,
        } = serde_json::from_slice(&bytes).map_err(|_| dummy_error())?;
        single(
            snapshot
                .list::<crate::user::User>("acc/")
                .filter_map(|(_, user)| {
                    if last_name != user.last_name_norm {
                        return None;
                    }
                    if first_name != user.first_name_norm {
                        return None;
                    }
                    if date_of_birth != user.date_of_birth {
                        return None;
                    }
                    Some(user)
                }),
        )
        .ok_or_else(dummy_error)
    }) {
        Ok(user) => {
            Snapshot::delete_and_wait_for_update([format!("sid/{}", session.id)].iter()).await;
            if user.create_session(snapshot, None, true).await.is_some() {
                let mut response = Response::builder();
                let headers = response.headers_mut().unwrap();
                session.cookies(false).into_iter().for_each(|cookie| {
                    headers.append(SET_COOKIE, cookie);
                });
                headers.insert(
                    LOCATION,
                    HeaderValue::from_static(USER_PATH_PREFIX.without_trailing_slash),
                );
                info!(
                    "307 {}/user/admin/login_as",
                    API_PATH_PREFIX.without_trailing_slash
                );
                response
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .body(Either::Right(Empty::new()))
                    .unwrap()
            } else {
                info!(
                    "500 {}/user/admin/login_as",
                    API_PATH_PREFIX.without_trailing_slash
                );
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Either::Right(Empty::new()))
                    .unwrap()
            }
        }
        Err(err) => {
            if err.downcast_ref::<serde_json::Error>().is_some() {
                info!(
                    "413 {}/user/admin/login_as",
                    API_PATH_PREFIX.without_trailing_slash
                );
                Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Either::Right(Empty::new()))
                    .unwrap()
            } else {
                info!(
                    "400 {}/user/admin/login_as",
                    API_PATH_PREFIX.without_trailing_slash
                );
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Either::Right(Empty::new()))
                    .unwrap()
            }
        }
    }
}
