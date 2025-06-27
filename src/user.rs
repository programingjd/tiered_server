use crate::env::ConfigurationKey::{AdminUsers, ValidationTotpSecret};
use crate::env::secret_value;
use crate::headers::{GET, GET_POST, JSON, POST};
use crate::norm::{
    DEFAULT_COUNTRY_CODE, normalize_email, normalize_first_name, normalize_last_name,
    normalize_phone_number,
};
use crate::otp::{Action, Otp};
use crate::server::DOMAIN_APEX;
use crate::session::{SESSION_MAX_AGE, SessionState};
use crate::store::{Snapshot, snapshot};
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ALLOW, CONTENT_TYPE, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use multer::{Constraints, Multipart, SizeLimit, parse_boundary};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rfc6238::TotpGenerator;
use tracing::{info, trace};

const TEXT: HeaderValue = HeaderValue::from_static("text/plain");
const SECS_PER_YEAR: u64 = 31_556_952;

//noinspection SpellCheckingInspection
static VALIDATION_TOTP_SECRET: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(ValidationTotpSecret));

#[derive(Clone, Serialize, Deserialize)]
pub struct Email {
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
pub struct Sms {
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
pub enum IdentificationMethod {
    Email(Email),
    Sms(Sms),
    NotSet,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub identification: IdentificationMethod,
    pub last_name: String,
    pub last_name_norm: String,
    pub first_name: String,
    pub first_name_norm: String,
    pub date_of_birth: u32,
    #[serde(skip_serializing_if = "is_default", default = "Default::default")]
    pub admin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    t == &T::default()
}

pub(crate) async fn ensure_admin_users_exist(snapshot: &Arc<Snapshot>) -> Option<()> {
    let value = secret_value(AdminUsers).unwrap_or("");
    let users = snapshot
        .list::<User>("acc/")
        .map(|(_, user)| user)
        .collect::<Vec<_>>();
    trace!(
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
            let server_name = DOMAIN_APEX.to_string();
            User::create(
                email.trim().to_string(),
                None,
                last_name.trim().to_string(),
                None,
                first_name.trim().to_string(),
                None,
                date_of_birth,
                true,
                false,
                true,
                snapshot,
                &Arc::new(server_name),
            )
            .await?;
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
        skip_notification: bool,
        snapshot: &Arc<Snapshot>,
        server_name: &Arc<String>,
    ) -> Option<Self> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let id = Self::new_id(timestamp);
        let identification = IdentificationMethod::Email(Email {
            normalized_address: email_norm.unwrap_or_else(|| normalize_email(&email)),
            address: email,
        });
        let key = format!("{}/{id}", if needs_validation { "reg" } else { "acc" });
        if snapshot.get::<User>(key.as_str()).is_some() {
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
            metadata: if needs_validation {
                Some(json!({"timestamp": timestamp}))
            } else {
                None
            },
        };
        Snapshot::set_and_wait_for_update(key.as_str(), &user).await?;
        if !needs_validation && !skip_notification {
            Otp::send(&user, Action::FirstLogin, None, snapshot, server_name).await?;
        }
        Some(user)
    }
    pub fn email(&self) -> Option<&str> {
        if let IdentificationMethod::Email(ref email) = self.identification {
            Some(email.normalized_address.as_str())
        } else {
            None
        }
    }
    pub fn sms(&self) -> Option<&str> {
        if let IdentificationMethod::Sms(ref number) = self.identification {
            Some(number.normalized_number.as_str())
        } else {
            None
        }
    }
    pub fn new_id(timestamp: u32) -> String {
        let mut random = [0u8; 36];
        random[32..].copy_from_slice(timestamp.to_be_bytes().as_slice());
        SystemRandom::new().fill(&mut random[..32]).unwrap();
        URL_SAFE_NO_PAD.encode_to_string(
            timestamp
                .to_le_bytes()
                .into_iter()
                .chain(random)
                .collect::<Vec<_>>(),
        )
    }
}

pub(crate) enum RequestOrResponse {
    Req(Request<Incoming>),
    Res(Response<Either<Full<Bytes>, Empty<Bytes>>>),
}

#[allow(clippy::inconsistent_digit_grouping)]
pub(crate) async fn handle_user(
    request: Request<Incoming>,
    server_name: &Arc<String>,
) -> RequestOrResponse {
    let path = &request.uri().path()[9..];
    if let Some(path) = path.strip_prefix("/admin") {
        let snapshot = snapshot();
        if SessionState::from_headers(request.headers(), &snapshot)
            .await
            .is_admin()
        {
            if path == "/registrations/code" {
                if let Some(secret) = *VALIDATION_TOTP_SECRET {
                    info!("200 https://{server_name}/api/user/admin/reg/code");
                    return RequestOrResponse::Res(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, TEXT)
                            .body(Either::Left(Full::from(secret)))
                            .unwrap(),
                    );
                }
            } else if path == "/users" || path == "/registrations" {
                if request.method() == Method::GET {
                    #[derive(Serialize)]
                    struct UserResponse {
                        first_name: String,
                        last_name: String,
                        date_of_birth: u32,
                        email: Option<String>,
                        sms: Option<String>,
                        #[serde(flatten, skip_serializing_if = "Option::is_none")]
                        metadata: Option<Value>,
                    }
                    let users = snapshot
                        .list::<User>(if path == "/users" { "acc/" } else { "reg/" })
                        .map(|(_, user)| {
                            let (email, sms) = match user.identification {
                                IdentificationMethod::Email(email) => {
                                    (Some(email.normalized_address), None)
                                }
                                IdentificationMethod::Sms(sms) => {
                                    (None, Some(sms.normalized_number))
                                }
                                _ => (None, None),
                            };
                            UserResponse {
                                first_name: user.first_name,
                                last_name: user.last_name,
                                date_of_birth: user.date_of_birth,
                                email,
                                sms,
                                metadata: user.metadata,
                            }
                        })
                        .collect::<Vec<_>>();
                    return RequestOrResponse::Res(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, JSON)
                            .body(Either::Left(Full::from(
                                serde_json::to_vec(&users).unwrap(),
                            )))
                            .unwrap(),
                    );
                } else if path == "/users" {
                    let mut response = Response::builder();
                    let headers = response.headers_mut().unwrap();
                    headers.insert(ALLOW, GET);
                    info!("405 https://{server_name}/api/user/admin/users");
                    return RequestOrResponse::Res(
                        response
                            .status(StatusCode::METHOD_NOT_ALLOWED)
                            .body(Either::Right(Empty::new()))
                            .unwrap(),
                    );
                } else {
                    if request.method() != Method::POST {
                        let mut response = Response::builder();
                        let headers = response.headers_mut().unwrap();
                        headers.insert(ALLOW, GET_POST);
                        info!("405 https://{server_name}/api/user/admin/registrations");
                        return RequestOrResponse::Res(
                            response
                                .status(StatusCode::METHOD_NOT_ALLOWED)
                                .body(Either::Right(Empty::new()))
                                .unwrap(),
                        );
                    }
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
                                if Snapshot::set_and_wait_for_update(
                                    format!("acc/{user_id}").as_str(),
                                    &user,
                                )
                                .await
                                .is_some()
                                    && Snapshot::delete([format!("reg/{user_id}").as_str()].iter())
                                        .await
                                        .is_some()
                                    && (skip_notification
                                        || Otp::send(
                                            &user,
                                            Action::FirstLogin,
                                            None,
                                            &snapshot,
                                            server_name,
                                        )
                                        .await
                                        .is_some())
                                {
                                    info!("202 https://{server_name}/api/user/admin/registrations");
                                    return RequestOrResponse::Res(
                                        Response::builder()
                                            .status(StatusCode::ACCEPTED)
                                            .body(Either::Right(Empty::new()))
                                            .unwrap(),
                                    );
                                }
                            }
                        }
                    }
                    info!("400 https://{server_name}/api/user/admin/registrations");
                    return RequestOrResponse::Res(
                        Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Either::Right(Empty::new()))
                            .unwrap(),
                    );
                }
            }
        } else {
            info!("403 https://{server_name}/api/user/admin{path}");
            return RequestOrResponse::Res(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Either::Right(Empty::new()))
                    .unwrap(),
            );
        }
    } else if path == "/email" {
        let snapshot = snapshot();
        if let SessionState::Valid { user, .. } =
            SessionState::from_headers(request.headers(), &snapshot).await
        {
            if request.method() == Method::POST {
                if let Some(value) = request.into_body().collect().await.ok().and_then(|it| {
                    let bytes = it.to_bytes();
                    if bytes.is_ascii() {
                        let email = String::from_utf8_lossy(&bytes);
                        let len = email.len();
                        if len > 5 && email[1..len - 4].contains('@') {
                            return Some(json!({
                                "new_email": email.as_ref()
                            }));
                        }
                    }
                    None
                }) {
                    if Otp::send(
                        &user,
                        Action::EmailUpdate,
                        Some(value),
                        &snapshot,
                        server_name,
                    )
                    .await
                    .is_some()
                    {
                        info!("202 https://{server_name}/api/user/email");
                        return RequestOrResponse::Res(
                            Response::builder()
                                .status(StatusCode::ACCEPTED)
                                .body(Either::Right(Empty::new()))
                                .unwrap(),
                        );
                    } else {
                        info!("500 https://{server_name}/api/user/email");
                        return RequestOrResponse::Res(
                            Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Either::Right(Empty::new()))
                                .unwrap(),
                        );
                    }
                } else {
                    info!("400 https://{server_name}/api/user/email");
                    return RequestOrResponse::Res(
                        Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Either::Right(Empty::new()))
                            .unwrap(),
                    );
                }
            } else {
                let mut response = Response::builder();
                let headers = response.headers_mut().unwrap();
                headers.insert(ALLOW, POST);
                info!("405 https://{server_name}/api/user/email");
                return RequestOrResponse::Res(
                    response
                        .status(StatusCode::METHOD_NOT_ALLOWED)
                        .body(Either::Right(Empty::new()))
                        .unwrap(),
                );
            }
        } else {
            info!("403 https://{server_name}/api/user/email");
            return RequestOrResponse::Res(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Either::Right(Empty::new()))
                    .unwrap(),
            );
        }
    } else if path == "/" || path.is_empty() {
        if request.method() == Method::POST {
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
                                info!("403 /api/user");
                                return RequestOrResponse::Res(
                                    Response::builder()
                                        .status(StatusCode::FORBIDDEN)
                                        .body(Either::Right(Empty::new()))
                                        .unwrap(),
                                );
                            }
                        } else {
                            true
                        }
                    } else {
                        true
                    };
                    let snapshot = snapshot();
                    let existing = snapshot.list::<User>("acc/").any(|(_, ref user)| {
                        if let IdentificationMethod::Email(ref email) = user.identification {
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
                            false,
                            &snapshot,
                            server_name,
                        )
                        .await;
                    }
                    info!("202 https://{server_name}/api/user");
                    return RequestOrResponse::Res(
                        Response::builder()
                            .status(StatusCode::ACCEPTED)
                            .body(Either::Right(Empty::new()))
                            .unwrap(),
                    );
                }
            }
            info!("400 https://{server_name}/api/user");
            return RequestOrResponse::Res(
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Either::Right(Empty::new()))
                    .unwrap(),
            );
        } else {
            let snapshot = snapshot();
            if let SessionState::Valid { user, session } =
                SessionState::from_headers(request.headers(), &snapshot).await
            {
                if request.method() == Method::GET {
                    let mut response = Response::builder();
                    response.headers_mut().unwrap().insert(CONTENT_TYPE, JSON);
                    let (email, sms) = match user.identification {
                        IdentificationMethod::Email(email) => {
                            (Some(email.normalized_address), None)
                        }
                        IdentificationMethod::Sms(sms) => (None, Some(sms.normalized_number)),
                        _ => (None, None),
                    };
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
                    info!("200 https://{server_name}/api/user");
                    return RequestOrResponse::Res(
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
                                    session_expiration_timestamp: session.timestamp
                                        + SESSION_MAX_AGE,
                                    session_from_passkey: session.passkey_id.is_some(),
                                    admin: user.admin,
                                    metadata: user.metadata,
                                })
                                .unwrap(),
                            )))
                            .unwrap(),
                    );
                } else {
                    let mut response = Response::builder();
                    let headers = response.headers_mut().unwrap();
                    headers.insert(ALLOW, GET_POST);
                    info!("405 https://{server_name}/api/user");
                    return RequestOrResponse::Res(
                        response
                            .status(StatusCode::METHOD_NOT_ALLOWED)
                            .body(Either::Right(Empty::new()))
                            .unwrap(),
                    );
                }
            }
        }
        info!("403 https://{server_name}/api/user");
        return RequestOrResponse::Res(
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Either::Right(Empty::new()))
                .unwrap(),
        );
    }
    RequestOrResponse::Req(request)
}
