use crate::store::Snapshot;
use crate::user::endpoints::admin::{UserOrRegistration, list};
use http_body_util::{Either, Empty, Full};
use hyper::Response;
use hyper::body::Bytes;
use std::sync::Arc;

pub(crate) async fn get(snapshot: &Arc<Snapshot>) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    list(snapshot, UserOrRegistration::User).await
}
