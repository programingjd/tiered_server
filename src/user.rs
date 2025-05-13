use crate::env::ConfigurationKey::{AdminUsers, ValidationTotpSecret};
use crate::env::secret_value;
use crate::headers::{GET_POST_PUT, JSON};
use crate::norm::{
    DEFAULT_COUNTRY_CODE, normalize_email, normalize_first_name, normalize_last_name,
    normalize_phone_number,
};
use crate::otp::Otp;
use crate::session::{SESSION_MAX_AGE, SessionState};
use crate::store::Snapshot;
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ALLOW, CONTENT_TYPE, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use multer::{Constraints, Multipart, SizeLimit, parse_boundary};
use pinboard::NonEmptyPinboard;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rfc6238::TotpGenerator;
use tracing::{debug, info};
use zip_static_handler::handler::Handler;

const TEXT: HeaderValue = HeaderValue::from_static("text/plain");
const SECS_PER_YEAR: u64 = 31_556_952;

//noinspection SpellCheckingInspection
static VALIDATION_TOTP_SECRET: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(ValidationTotpSecret));

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Email {
    pub(crate) address: String,
    pub(crate) normalized_address: String,
}

impl From<String> for Email {
    fn from(value: String) -> Self {
        Self {
            normalized_address: normalize_email(&value),
            address: value,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Sms {
    number: String,
    normalized_number: String,
}

impl From<String> for Sms {
    fn from(value: String) -> Self {
        Self {
            normalized_number: normalize_phone_number(&value, *DEFAULT_COUNTRY_CODE),
            number: value,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum IdentificationMethod {
    Email(Email),
    Sms(Sms),
    NotSet,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub(crate) identification: IdentificationMethod,
    pub last_name: String,
    pub last_name_norm: String,
    pub first_name: String,
    pub first_name_norm: String,
    pub date_of_birth: u32,
    #[serde(skip_serializing_if = "is_default")]
    pub admin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    t == &T::default()
}

pub(crate) async fn ensure_admin_users_exist(
    store_cache: &Arc<NonEmptyPinboard<Snapshot>>,
    handler: Arc<Handler>,
) -> Option<()> {
    let value = secret_value(AdminUsers).unwrap_or("");
    let users = store_cache
        .get_ref()
        .list::<User>("acc/")
        .map(|(_, user)| user)
        .collect::<Vec<_>>();
    debug!(
        "users:\n{}",
        users
            .iter()
            .map(|it| format!(
                "    {} {} {}",
                match it.identification {
                    IdentificationMethod::Email(ref email) => email.address.as_str(),
                    _ => "?",
                },
                it.last_name.as_str(),
                it.first_name.as_str()
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
    for user in value.split(";") {
        let mut iter = user.split(",");
        let email = iter.next()?;
        let last_name = iter.next()?;
        let first_name = iter.next()?;
        let date_of_birth = iter.next()?.parse::<u32>().ok()?;
        let email_norm = normalize_email(email);
        let last_name_norm = normalize_last_name(last_name);
        let first_name_norm = normalize_first_name(first_name);
        if !users.iter().any(|user| {
            if let IdentificationMethod::Email(Email {
                ref normalized_address,
                ..
            }) = user.identification
            {
                normalized_address == &email_norm
                    && user.last_name_norm == last_name_norm
                    && user.first_name_norm == first_name_norm
                    && user.date_of_birth == date_of_birth
            } else {
                false
            }
        }) {
            info!("new admin account: {email} {last_name} {first_name}");
            if let Some(user) = User::create(
                email.trim().to_string(),
                None,
                last_name.trim().to_string(),
                None,
                first_name.trim().to_string(),
                None,
                date_of_birth,
                true,
                false,
                store_cache,
            )
            .await
            {
                Otp::send(
                    &user,
                    store_cache,
                    &handler,
                    Arc::new("localhost".to_string()),
                )
                .await?;
            }
        }
    }
    Some(())
}

impl User {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn create(
        email: String,
        email_norm: Option<String>,
        last_name: String,
        last_name_norm: Option<String>,
        first_name: String,
        first_name_norm: Option<String>,
        date_of_birth: u32, // yyyyMMdd
        admin: bool,
        needs_validation: bool,
        store_cache: &Arc<NonEmptyPinboard<Snapshot>>,
    ) -> Option<Self> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let mut random = [0u8; 36];
        random[32..].copy_from_slice(timestamp.to_be_bytes().as_slice());
        SystemRandom::new().fill(&mut random[..32]).unwrap();
        let id = URL_SAFE_NO_PAD.encode_to_string(
            timestamp
                .to_le_bytes()
                .into_iter()
                .chain(random.into_iter())
                .collect::<Vec<_>>(),
        );
        let identification = IdentificationMethod::Email(Email {
            normalized_address: email_norm.unwrap_or_else(|| normalize_email(&email)),
            address: email,
        });
        let key = format!("{}/{id}", if needs_validation { "reg" } else { "acc" });
        if store_cache.get_ref().get::<User>(key.as_str()).is_some() {
            return None;
        }
        let first_name_norm =
            first_name_norm.unwrap_or_else(|| normalize_first_name(first_name.as_str()));
        let last_name_norm =
            last_name_norm.unwrap_or_else(|| normalize_last_name(last_name.as_str()));
        let user = Self {
            id,
            identification,
            last_name,
            last_name_norm,
            first_name,
            first_name_norm,
            date_of_birth,
            admin,
            metadata: None,
        };
        Snapshot::set(key.as_str(), &user).await?;
        Some(user)
    }
}

#[allow(clippy::inconsistent_digit_grouping)]
pub(crate) async fn handle_user(
    request: Request<Incoming>,
    store_cache: &Arc<NonEmptyPinboard<Snapshot>>,
    server_name: Arc<String>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = &request.uri().path()[9..];
    if path == "/admin/reg/code" {
        if let SessionState::Valid { user, .. } =
            SessionState::from_headers(request.headers(), store_cache).await
        {
            if user.admin {
                if let Some(secret) = *VALIDATION_TOTP_SECRET {
                    debug!("200 https://{server_name}/api/user/admin/reg/code");
                    return Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, TEXT)
                        .body(Either::Left(Full::from(secret)))
                        .unwrap();
                }
            }
        }
        debug!("403 /api/user/admin/reg/code");
    } else if path == "/" || path.is_empty() {
        if request.method() == Method::PUT {
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
                                debug!("403 /api/user");
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
                    let existing =
                        store_cache
                            .get_ref()
                            .list::<User>("acc/")
                            .any(|(_, ref user)| {
                                if let IdentificationMethod::Email(ref email) = user.identification
                                {
                                    email_norm == email.normalized_address
                                        && user.date_of_birth == dob
                                        && user.last_name_norm == last_name_norm
                                        && user.first_name_norm == first_name_norm
                                } else {
                                    false
                                }
                            });
                    if !existing {
                        let email_trim = email.trim();
                        let last_name_trim = last_name.trim();
                        let first_name_trim = first_name.trim();
                        let _ = User::create(
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
                            store_cache,
                        )
                        .await;
                        if !needs_moderation {
                            // TODO send email
                        }
                    }
                    debug!("202 https://{server_name}/api/user");
                    return Response::builder()
                        .status(StatusCode::ACCEPTED)
                        .body(Either::Right(Empty::new()))
                        .unwrap();
                }
            }
            debug!("400 https://{server_name}/api/user");
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Either::Right(Empty::new()))
                .unwrap();
        } else if let SessionState::Valid { user, session } =
            SessionState::from_headers(request.headers(), store_cache).await
        {
            if request.method() == Method::GET {
                let mut response = Response::builder();
                response.headers_mut().unwrap().insert(CONTENT_TYPE, JSON);
                debug!("200 https://{server_name}/api/user");
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, JSON)
                    .body(Either::Left(Full::from(
                        serde_json::to_vec(&json!({
                            "first_name": user.first_name,
                            "last_name": user.last_name,
                            "date_of_birth": user.date_of_birth,
                            "email": match &user.identification {
                                IdentificationMethod::Email(email) => Some(&email.normalized_address),
                                _ => None
                            },
                            "sms": match &user.identification {
                                IdentificationMethod::Sms(sms) => Some(&sms.normalized_number),
                                _ => None
                            },
                            "session_expiration_timestamp": session.timestamp + SESSION_MAX_AGE,
                            "session_from_passkey": session.passkey_id.is_some(),
                            "admin": user.admin,
                        })).unwrap(),
                    )))
                    .unwrap();
            } else if request.method() == Method::POST {
                // TODO update user field
            } else {
                let mut response = Response::builder();
                let headers = response.headers_mut().unwrap();
                headers.insert(ALLOW, GET_POST_PUT);
                debug!("405 https://{server_name}/api/user");
                return response
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Either::Right(Empty::new()))
                    .unwrap();
            }
        }
        debug!("403 https://{server_name}/api/user");
    }
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Either::Right(Empty::new()))
        .unwrap()
}
