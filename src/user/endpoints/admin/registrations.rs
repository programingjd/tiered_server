use crate::otp::Otp;
use crate::otp::action::Event;
use crate::prefix::API_PATH_PREFIX;
use crate::store::Snapshot;
use crate::user::User;
use crate::user::endpoints::admin::{UserOrRegistration, list};
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::{Request, Response, StatusCode};
use multer::{Constraints, Multipart, SizeLimit, parse_boundary};
use std::sync::Arc;
use tracing::info;

pub(crate) async fn get(snapshot: &Arc<Snapshot>) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    list(snapshot, UserOrRegistration::Registration).await
}

pub(crate) async fn post(
    request: Request<Incoming>,
    server_name: &Arc<String>,
    snapshot: &Arc<Snapshot>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    if let Some(boundary) = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|it| it.to_str().ok())
        .and_then(|it| parse_boundary(it).ok())
    {
        let mut multipart = Multipart::with_constraints(
            request.into_body().into_data_stream(),
            boundary,
            Constraints::new().size_limit(SizeLimit::new().whole_stream(4_096)),
        );
        let mut user_id = None;
        let mut skip_notification = false;
        while let Ok(Some(field)) = multipart.next_field().await {
            match field.name() {
                Some("user_id") => {
                    if let Ok(it) = field.text().await {
                        user_id = Some(it);
                    }
                }
                Some("skip_notification") => {
                    if let Ok(it) = field.text().await {
                        if let Ok(b) = it.parse::<bool>() {
                            skip_notification = b;
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(user_id) = user_id {
            let user = snapshot.get::<User>(user_id.as_str());
            if let Some(mut user) = user {
                user.metadata = None;
                if Snapshot::set_and_return_before_update(format!("acc/{user_id}").as_str(), &user)
                    .await
                    .is_some()
                    && Snapshot::delete_and_wait_for_update(
                        [format!("reg/{user_id}").as_str()].iter(),
                    )
                    .await
                    .is_some()
                    && (skip_notification
                        || Otp::send(&user, Event::FirstLogin, None, snapshot, server_name)
                            .await
                            .is_some())
                {
                    info!(
                        "202 {}/user/admin/registrations",
                        API_PATH_PREFIX.without_trailing_slash
                    );
                    return Response::builder()
                        .status(StatusCode::ACCEPTED)
                        .body(Either::Right(Empty::new()))
                        .unwrap();
                }
            }
        }
    }
    info!(
        "400 {}/user/admin/registrations",
        API_PATH_PREFIX.without_trailing_slash
    );
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Either::Right(Empty::new()))
        .unwrap()
}
