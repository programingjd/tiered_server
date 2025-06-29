use crate::headers::JSON;
use crate::norm::{normalize_email, normalize_first_name, normalize_last_name};
use crate::otp::Otp;
use crate::otp::action::Action;
use crate::prefix::API_PATH_PREFIX;
use crate::session::{SESSION_MAX_AGE, SessionState};
use crate::store::snapshot;
use crate::user::{IdentificationMethod, User, VALIDATION_TOTP_SECRET};
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::{Request, Response, StatusCode};
use multer::{Constraints, Multipart, SizeLimit, parse_boundary};
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::spawn;
use totp_rfc6238::TotpGenerator;
use tracing::info;

const SECS_PER_YEAR: u64 = 31_556_952;

#[allow(clippy::inconsistent_digit_grouping)]
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
            Constraints::new().size_limit(SizeLimit::new().whole_stream(4096)),
        );
        let mut email = None;
        let mut last_name = None;
        let mut first_name = None;
        let mut dob = None;
        let mut otp = None;
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
                        dob = it.parse::<u32>().ok()
                    }
                }
                Some("otp") => {
                    if let Ok(it) = field.text().await {
                        otp = Some(it);
                    }
                }
                _ => {}
            }
        }
        let dob = dob.filter(|&it| {
            let max_dob = ((SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                / SECS_PER_YEAR
                + 1969)
                * 1_00_00) as u32;
            it < max_dob && it > 1900_00_00_u32
        });
        if email.is_some() && last_name.is_some() && first_name.is_some() && dob.is_some() {
            let email = email.unwrap();
            let email_norm = normalize_email(&email);
            let last_name = last_name.unwrap();
            let last_name_norm = normalize_last_name(&last_name);
            let first_name = first_name.unwrap();
            let first_name_norm = normalize_first_name(&first_name);
            let dob = dob.unwrap();
            let needs_moderation = if let Some(otp) = otp {
                if let Some(key) = *VALIDATION_TOTP_SECRET {
                    let generator = TotpGenerator::new().build();
                    if generator
                        .get_code_window(key.as_bytes(), -1..=1)
                        .map(|it| it.contains(&otp))
                        .unwrap_or(false)
                    {
                        false
                    } else {
                        info!("403 {}/user", API_PATH_PREFIX.without_trailing_slash);
                        return Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Either::Right(Empty::new()))
                            .unwrap();
                    }
                } else {
                    true
                }
            } else {
                true
            };
            let snapshot = snapshot();
            let user = snapshot.list::<User>("acc/").find_map(|(_, user)| {
                if let IdentificationMethod::Email(ref email) = user.identification {
                    if email_norm == email.normalized_address
                        && user.date_of_birth == dob
                        && user.last_name_norm == last_name_norm
                        && user.first_name_norm == first_name_norm
                    {
                        Some(user)
                    } else {
                        None
                    }
                } else {
                    None
                }
            });
            if let Some(user) = user {
                let server_name = server_name.clone();
                #[allow(clippy::let_underscore_future)]
                let _ = spawn(async move {
                    Otp::send(&user, Action::Login, None, &snapshot, &server_name).await
                });
            } else {
                let email_trim = email.trim();
                let last_name_trim = last_name.trim();
                let first_name_trim = first_name.trim();
                let _user = User::create(
                    if email.len() == email_trim.len() {
                        email
                    } else {
                        email_trim.to_string()
                    },
                    Some(email_norm),
                    if last_name.len() == last_name_trim.len() {
                        last_name
                    } else {
                        last_name_trim.to_string()
                    },
                    Some(last_name_norm),
                    if first_name.len() == first_name_trim.len() {
                        first_name
                    } else {
                        first_name_trim.to_string()
                    },
                    Some(first_name_norm),
                    dob,
                    false,
                    needs_moderation,
                    false,
                    &snapshot,
                    server_name,
                )
                .await;
            }
            info!("202 {}/user", API_PATH_PREFIX.without_trailing_slash);
            return Response::builder()
                .status(StatusCode::ACCEPTED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
    }
    info!("400 {}/user", API_PATH_PREFIX.without_trailing_slash);
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Either::Right(Empty::new()))
        .unwrap()
}

#[derive(Serialize)]
struct UserResponse {
    first_name: String,
    last_name: String,
    date_of_birth: u32,
    email: Option<String>,
    sms: Option<String>,
    session_expiration_timestamp: u32,
    session_from_passkey: bool,
    admin: bool,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
}

pub(crate) async fn get(request: Request<Incoming>) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let snapshot = snapshot();
    if let SessionState::Valid { user, session } =
        SessionState::from_headers(request.headers(), &snapshot)
    {
        let mut response = Response::builder();
        response.headers_mut().unwrap().insert(CONTENT_TYPE, JSON);
        let (email, sms) = match user.identification {
            IdentificationMethod::Email(email) => (Some(email.normalized_address), None),
            IdentificationMethod::Sms(sms) => (None, Some(sms.normalized_number)),
            _ => (None, None),
        };
        info!("200 {}/api/user", API_PATH_PREFIX.without_trailing_slash);
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, JSON)
            .body(Either::Left(Full::from(
                serde_json::to_vec(&UserResponse {
                    first_name: user.first_name,
                    last_name: user.last_name,
                    date_of_birth: user.date_of_birth,
                    email,
                    sms,
                    session_expiration_timestamp: session.timestamp + SESSION_MAX_AGE,
                    session_from_passkey: session.passkey_id.is_some(),
                    admin: user.admin,
                    metadata: user.metadata,
                })
                .unwrap(),
            )))
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Either::Right(Empty::new()))
            .unwrap()
    }
}
