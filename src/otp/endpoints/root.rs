use crate::api::{Action, Extension};
use crate::env::ConfigurationKey::{ApiErrorOtpAlreadyUsed, ApiErrorOtpExpired};
use crate::env::secret_value;
use crate::handler::static_handler;
use crate::iter::single;
use crate::norm::{normalize_email, normalize_first_name, normalize_last_name};
use crate::otp::action::Event;
use crate::otp::signature::token_signature;
use crate::otp::{OTP_VALIDITY_DURATION, Otp};
use crate::prefix::API_PATH_PREFIX;
use crate::store::{Snapshot, snapshot};
use crate::user::{IdentificationMethod, User};
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{
    CONTENT_TYPE, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_UNMODIFIED_SINCE,
};
use hyper::http::uri::PathAndQuery;
use hyper::{Request, Response, StatusCode, Uri};
use multer::{Constraints, Multipart, SizeLimit, parse_boundary};
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;
use tokio::spawn;
use tracing::{debug, info};

pub(crate) async fn post(
    request: Request<Incoming>,
    server_name: &Arc<String>,
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
        let mut email = None;
        let mut last_name = None;
        let mut first_name = None;
        let mut dob = None;
        while let Ok(Some(field)) = multipart.next_field().await {
            match field.name() {
                Some("email") => {
                    if let Ok(it) = field.text().await {
                        email = Some(it);
                    }
                }
                Some("last_name") => {
                    if let Ok(it) = field.text().await {
                        last_name = Some(it);
                    }
                }
                Some("first_name") => {
                    if let Ok(it) = field.text().await {
                        first_name = Some(it);
                    }
                }
                Some("dob") => {
                    if let Ok(it) = field.text().await {
                        dob = it.parse::<u32>().ok();
                    }
                }
                _ => {}
            }
        }
        let email_norm = email.as_ref().map(|it| normalize_email(it));
        let last_name_norm = last_name.as_ref().map(|it| normalize_last_name(it));
        let first_name_norm = first_name.as_ref().map(|it| normalize_first_name(it));
        let snapshot = snapshot();
        let single = single(snapshot.list::<User>("acc/").filter_map(|(_, user)| {
            if let Some(ref email_norm) = email_norm {
                if !user.identification.iter().any(|it| {
                    if let IdentificationMethod::Email(e) = it {
                        email_norm == &e.normalized_address
                    } else {
                        false
                    }
                }) {
                    return None;
                }
            }
            if let Some(ref last_name_norm) = last_name_norm {
                if last_name_norm != &user.last_name_norm {
                    return None;
                }
            }
            if let Some(ref first_name_norm) = first_name_norm {
                if first_name_norm != &user.first_name_norm {
                    return None;
                }
            }
            if let Some(dob) = dob {
                if dob != user.date_of_birth {
                    return None;
                }
            }
            Some(user)
        }));
        if let Some(user) = single {
            let server_name = server_name.clone();
            #[allow(clippy::let_underscore_future)]
            let _ = spawn(async move {
                Otp::send(&user, Event::Login, None, &snapshot, &server_name).await
            });
        }
    }
    info!("202 {}/otp", API_PATH_PREFIX.without_trailing_slash);
    Response::builder()
        .status(StatusCode::ACCEPTED)
        .body(Either::Right(Empty::new()))
        .unwrap()
}

//noinspection SpellCheckingInspection
static API_ERROR_OTP_EXPIRED: LazyLock<&'static str> =
    LazyLock::new(|| secret_value(ApiErrorOtpExpired).unwrap_or("otp-expired"));
//noinspection SpellCheckingInspection
static API_ERROR_OTP_ALREADY_USED: LazyLock<&'static str> =
    LazyLock::new(|| secret_value(ApiErrorOtpAlreadyUsed).unwrap_or("otp-already-used"));

pub(crate) async fn get<Ext: Extension + Send + Sync>(
    request: Request<Incoming>,
    extension: &Ext,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let payload = request
        .uri()
        .path()
        .strip_prefix(API_PATH_PREFIX.without_trailing_slash)
        .unwrap()
        .strip_prefix("/otp/")
        .unwrap();
    let mut iter = payload.split('.');
    let token = iter.next();
    let signature = iter.next();
    if let Some(signature) = signature {
        let token = token.unwrap();
        if let Some(signed) = token_signature(token) {
            if signed.as_str() == signature {
                let snapshot = snapshot();
                let timestamp = URL_SAFE_NO_PAD
                    .decode_to_vec(token)
                    .ok()
                    .and_then(|it| it[32..].try_into().ok().map(u32::from_be_bytes));
                return if let Some(timestamp) = timestamp {
                    let key = format!("otp/{token}");
                    let otp = snapshot.get::<Otp>(key.as_str());
                    if let Some(otp) = otp {
                        let _ = Snapshot::delete_and_wait_for_update([key.as_str()].iter()).await;
                        if otp.timestamp != 0 {
                            let now = SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as u32;
                            let elapsed = now - timestamp;
                            let duration = otp.event.otp_validity_duration().unwrap_or(0);
                            if otp.timestamp != timestamp + duration || timestamp > now + duration {
                                if otp.timestamp != timestamp + duration {
                                    debug!(
                                        "otp timestamp {} != {timestamp} + {duration}",
                                        otp.timestamp
                                    );
                                } else {
                                    debug!("otp timestamp {timestamp} > {now} (now) + {duration}");
                                }
                                info!(
                                    "400 {}/otp/{payload}",
                                    API_PATH_PREFIX.without_trailing_slash
                                );
                                return Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .body(Either::Right(Empty::new()))
                                    .unwrap();
                            }
                            if elapsed > OTP_VALIDITY_DURATION {
                                info!(
                                    "410 {}/otp/{payload}",
                                    API_PATH_PREFIX.without_trailing_slash
                                );
                                let mut response = error_page(request, *API_ERROR_OTP_EXPIRED);
                                *response.status_mut() = StatusCode::GONE;
                                return response;
                            }
                        } else if otp.event.otp_validity_duration().is_some() {
                            return Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Either::Right(Empty::new()))
                                .unwrap();
                        }
                        let key = format!("acc/{}", otp.user_id);
                        if let Some(user) = snapshot.get::<User>(key.as_str()) {
                            if extension
                                .perform_action(&user, Action::Otp(otp.event), otp.data.as_ref())
                                .await
                                .is_some()
                            {
                                if let Some(response) =
                                    otp.event.handle(user, otp.data, &snapshot).await
                                {
                                    info!(
                                        "{} {}/otp/{payload}",
                                        response.status().as_u16(),
                                        API_PATH_PREFIX.without_trailing_slash
                                    );
                                    return response;
                                }
                            }
                        }
                        info!(
                            "500 {}/otp/{payload}",
                            API_PATH_PREFIX.without_trailing_slash
                        );
                        Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Either::Right(Empty::new()))
                            .unwrap()
                    } else {
                        info!(
                            "409 {}/otp/{payload}",
                            API_PATH_PREFIX.without_trailing_slash
                        );
                        let mut response = error_page(request, *API_ERROR_OTP_ALREADY_USED);
                        *response.status_mut() = StatusCode::CONFLICT;
                        response
                    }
                } else {
                    info!(
                        "400 {}/otp/{payload}",
                        API_PATH_PREFIX.without_trailing_slash
                    );
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Either::Right(Empty::new()))
                        .unwrap()
                };
            }
        }
    }
    info!(
        "404 {}/otp/{payload}",
        API_PATH_PREFIX.without_trailing_slash
    );
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Either::Right(Empty::new()))
        .unwrap()
}

pub(crate) fn error_page(
    mut request: Request<Incoming>,
    error_name: &str,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let headers = request.headers_mut();
    headers.remove(IF_MATCH);
    headers.remove(IF_NONE_MATCH);
    headers.remove(IF_MODIFIED_SINCE);
    headers.remove(IF_UNMODIFIED_SINCE);
    let uri = request.uri().clone();
    let mut uri_parts = uri.into_parts();
    uri_parts.path_and_query = Some(
        PathAndQuery::try_from(format!(
            "{}{error_name}",
            API_PATH_PREFIX.with_trailing_slash
        ))
        .unwrap(),
    );
    *request.uri_mut() = Uri::from_parts(uri_parts).unwrap();
    static_handler().handle_hyper_request(request)
}
