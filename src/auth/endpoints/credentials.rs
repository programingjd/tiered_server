use crate::auth::passkey::PassKey;
use crate::prefix::API_PATH_PREFIX;
use crate::store::Snapshot;
use crate::user::User;
use http_body_util::{Either, Empty, Full};
use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use std::sync::Arc;
use tracing::{debug, info};

pub(crate) fn head(
    snapshot: &Arc<Snapshot>,
    user: User,
) -> Option<Response<Either<Full<Bytes>, Empty<Bytes>>>> {
    Some(
        if let Some(first) = snapshot.list::<PassKey>(&format!("pk/{}/", user.id)).next() {
            debug!("passkey: {}", first.0);
            info!(
                "204 {}/auth/credentials",
                API_PATH_PREFIX.without_trailing_slash
            );
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Either::Right(Empty::new()))
                .unwrap()
        } else {
            info!(
                "404 {}/auth/credentials",
                API_PATH_PREFIX.without_trailing_slash
            );
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Either::Right(Empty::new()))
                .unwrap()
        },
    )
}
