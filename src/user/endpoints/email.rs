use crate::api::Extension;
use crate::norm::normalize_email;
use crate::prefix::API_PATH_PREFIX;
use crate::session::SessionState;
use crate::store::{Snapshot, snapshot};
use crate::totp::Totp;
use crate::totp::action::{Action, EmailAddition, EmailUpdate};
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::{Request, Response, StatusCode};
use multer::{Constraints, Multipart, SizeLimit, parse_boundary};
use tracing::info;

pub(crate) async fn post<Ext: Extension + Send + Sync>(
    request: Request<Incoming>,
    extension: &Ext,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let snapshot = snapshot();
    if let SessionState::Valid { user, .. } =
        SessionState::from_headers(request.headers(), &snapshot)
    {
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
            let mut old_email = None;
            let mut new_email = None;
            let mut totp = None;
            while let Ok(Some(field)) = multipart.next_field().await {
                match field.name() {
                    Some("old_email") => {
                        if let Ok(it) = field.text().await {
                            old_email = Some(it);
                        }
                    }
                    Some("new_email") => {
                        if let Ok(it) = field.text().await {
                            new_email = Some(it);
                        }
                    }
                    Some("totp") => {
                        if let Ok(it) = field.text().await {
                            totp = Some(it);
                        }
                    }
                    _ => {}
                }
            }
            if new_email.is_some() {
                let new_address = new_email.unwrap();
                let normalized_new_address = normalize_email(&new_address);
                let action = if let Some(old_email) = old_email {
                    let normalized_old_address = normalize_email(&old_email);
                    Action::UpdateEmail(EmailUpdate {
                        normalized_old_address,
                        normalized_new_address,
                        new_address,
                    })
                } else {
                    Action::AddEmail(EmailAddition {
                        normalized_new_address,
                        new_address,
                    })
                };
                if let Some(code) = totp {
                    let key = format!("rng/{}/{}", user.id, action.id());
                    if let Some(mut totp) = snapshot.get::<Totp>(&key) {
                        if totp.action == action && totp.is_valid() {
                            if totp.verify(&code) {
                                if extension
                                    .perform_action(&user, crate::api::Action::Totp(totp.action))
                                    .await
                                    .is_some()
                                {
                                    if let Some(response) = action.handle(user).await {
                                        return response;
                                    }
                                }
                            } else {
                                totp.retries += 1;
                                Snapshot::set_and_wait_for_update(&key, &totp).await;
                            }
                        }
                    }
                } else if let Some(totp) = Totp::create(&user, action, &snapshot).await {
                    return if totp.send(&user).await.is_some() {
                        info!("202 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
                        Response::builder()
                            .status(StatusCode::ACCEPTED)
                            .body(Either::Right(Empty::new()))
                            .unwrap()
                    } else {
                        info!("500 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
                        Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Either::Right(Empty::new()))
                            .unwrap()
                    };
                }
            }
        }
        info!("400 {}/otp/email", API_PATH_PREFIX.without_trailing_slash);
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Either::Right(Empty::new()))
            .unwrap()
    } else {
        info!("403 {}/user/email", API_PATH_PREFIX.without_trailing_slash);
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Either::Right(Empty::new()))
            .unwrap()
    }
}
