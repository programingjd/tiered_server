use crate::email::Email;
use crate::env::ConfigurationKey::{
    EmailOneTimeLoginTemplate, EmailOneTimeLoginTitle, OtpSigningKey,
};
use crate::env::secret_value;
use crate::headers::GET;
use crate::norm::{normalize_email, normalize_first_name, normalize_last_name};
use crate::prefix::{API_PATH_PREFIX, USER_PATH_PREFIX};
use crate::store::Snapshot;
use crate::user::{IdentificationMethod, User};
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ALLOW, CONTENT_TYPE, HeaderValue, LOCATION, SET_COOKIE};
use hyper::{Method, Request, Response, StatusCode};
use minijinja::Environment;
use multer::{Constraints, Multipart, SizeLimit, parse_boundary};
use pinboard::NonEmptyPinboard;
use ring::hmac::{HMAC_SHA256, Key, sign};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::str::from_utf8;
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;
use tokio::spawn;
use tracing::{debug, warn};
use zip_static_handler::handler::Handler;

//noinspection SpellCheckingInspection
static SIGNING_KEY: LazyLock<&'static str> = LazyLock::new(|| {
    secret_value(OtpSigningKey).unwrap_or("A8UVAbg0L_ZCsirPCsdxqe5GmaFRa1NSfUkc3Evsu2k")
});

//noinspection SpellCheckingInspection
static EMAIL_ONE_TIME_LOGIN_TITLE: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailOneTimeLoginTitle));
//noinspection SpellCheckingInspection
static EMAIL_ONE_TIME_LOGIN_TEMPLATE: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailOneTimeLoginTemplate));

const OTP_VALIDITY_DURATION: u32 = 1_200; // 20 mins

#[derive(Clone, Serialize, Deserialize)]
pub struct Otp {
    id: String,
    user_id: String,
    timestamp: u32,
}

#[derive(Serialize)]
struct NewCredentialsContext<'a> {
    user: &'a User,
    link_url: &'a str,
}

impl Otp {
    pub async fn send(
        user: &User,
        store_cache: &Arc<NonEmptyPinboard<Snapshot>>,
        handler: &Arc<Handler>,
        server_name: Arc<String>,
    ) -> Option<()> {
        let email = match &user.identification {
            IdentificationMethod::Email(email) => email.address.as_str(),
            _ => return None,
        };
        let otp = Self::create(user, store_cache).await?;
        let id = otp.id.as_str();
        let signature = token_signature(id).expect("token should be url safe base64 encoded");
        let link_url = format!(
            "https://{server_name}{}otp/{id}.{signature}",
            API_PATH_PREFIX.with_trailing_slash
        );
        let subject = (*EMAIL_ONE_TIME_LOGIN_TITLE)?;
        let template_name = (*EMAIL_ONE_TIME_LOGIN_TEMPLATE)?;
        let content = match handler
            .entry(&format!(
                "{}{template_name}",
                API_PATH_PREFIX.with_trailing_slash
            ))
            .and_then(|it| it.content.clone())
        {
            Some(content) => content,
            None => {
                warn!(
                    "missing email template: {}{template_name}",
                    API_PATH_PREFIX.with_trailing_slash
                );
                return None;
            }
        };
        let html_body = match from_utf8(content.as_ref()) {
            Ok(jinja) => {
                let mut environment = Environment::new();
                match environment.add_template("new_credentials", jinja) {
                    Ok(()) => environment.get_template("new_credentials"),
                    Err(err) => {
                        warn!(
                            "invalid template: {}{template_name}:\n{err:?}",
                            API_PATH_PREFIX.with_trailing_slash
                        );
                        return None;
                    }
                }
                .and_then(|template| {
                    template.render(NewCredentialsContext {
                        user,
                        link_url: link_url.as_str(),
                    })
                })
            }
            Err(_) => {
                warn!(
                    "invalid template: {}{template_name}",
                    API_PATH_PREFIX.with_trailing_slash
                );
                return None;
            }
        };
        let html_body = match html_body {
            Ok(html_body) => html_body,
            Err(err) => {
                warn!(
                    "invalid template: {}{template_name}:\n{err:?}",
                    API_PATH_PREFIX.with_trailing_slash
                );
                return None;
            }
        };
        #[cfg(debug_assertions)]
        let send = false;
        #[cfg(not(debug_assertions))]
        let send = true;
        if send {
            Email::send(email, subject, html_body.as_str()).await
        } else {
            println!("\x1b[34;49;4m{link_url}\x1b[0m");
            Some(())
        }
    }

    async fn create(user: &User, store_cache: &Arc<NonEmptyPinboard<Snapshot>>) -> Option<Self> {
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
        let key = format!("otp/{id}");
        let otp = Self {
            id,
            user_id: user.id.clone(),
            timestamp,
        };
        let _ = Self::remove_expired(store_cache, Some(user.id.as_str())).await;
        Snapshot::set(key.as_str(), &otp).await?;
        Some(otp)
    }

    async fn remove_expired(
        store_cache: &Arc<NonEmptyPinboard<Snapshot>>,
        user_id: Option<&str>,
    ) -> Option<()> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let paths: Vec<String> = store_cache
            .get_ref()
            .list::<Otp>("opt/")
            .filter_map(|(k, otp)| {
                let elapsed = timestamp - otp.timestamp;
                if otp.timestamp > timestamp || elapsed > OTP_VALIDITY_DURATION {
                    Some(k.to_string())
                } else if let Some(user_id) = user_id {
                    if otp.user_id == user_id {
                        Some(k.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Snapshot::delete(paths.iter()).await
    }
}

pub(crate) fn token_signature(token: &str) -> Option<String> {
    let payload = URL_SAFE_NO_PAD.decode_to_vec(token).ok()?;
    let key = Key::new(HMAC_SHA256, SIGNING_KEY.as_bytes());
    Some(URL_SAFE_NO_PAD.encode_to_string(sign(&key, &payload).as_ref()))
}

pub(crate) async fn handle_otp(
    request: Request<Incoming>,
    store_cache: &Arc<NonEmptyPinboard<Snapshot>>,
    handler: Arc<Handler>,
    server_name: Arc<String>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = &request.uri().path()[8..];
    if request.method() == Method::POST {
        if path == "/" || path.is_empty() {
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
                let single = single(store_cache.get_ref().list::<User>("acc/").filter_map(
                    |(_, user)| {
                        if let Some(ref email_norm) = email_norm {
                            if let IdentificationMethod::Email(ref e) = user.identification {
                                if email_norm != &e.normalized_address {
                                    return None;
                                }
                            } else {
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
                    },
                ));
                if let Some(user) = single {
                    let handler = handler.clone();
                    let server_name = server_name.clone();
                    let store_cache = store_cache.clone();
                    #[allow(clippy::let_underscore_future)]
                    let _ = spawn(async move {
                        Otp::send(&user, &store_cache, &handler, server_name).await
                    });
                }
            }
            debug!("202 https://{server_name}/api/otp");
            return Response::builder()
                .status(StatusCode::ACCEPTED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
    } else {
        if request.method() != Method::GET {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, GET);
            debug!("405 https://{server_name}/api/otp{path}");
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        let payload = &path[1..];
        let mut iter = payload.split('.');
        let token = iter.next();
        let signature = iter.next();
        if let Some(signature) = signature {
            let token = token.unwrap();
            if let Some(signed) = token_signature(token) {
                if signed.as_str() == signature {
                    if let Some(user) = validate_otp(token, store_cache).await {
                        if let Some(session) =
                            User::create_session(&user.id, store_cache, None).await
                        {
                            let mut response = Response::builder();
                            let headers = response.headers_mut().unwrap();
                            session.cookies().into_iter().for_each(|cookie| {
                                headers.append(SET_COOKIE, cookie);
                            });
                            headers.insert(
                                LOCATION,
                                HeaderValue::from_static(USER_PATH_PREFIX.without_trailing_slash),
                            );
                            debug!("307 /api/otp{path}");
                            return response
                                .status(StatusCode::TEMPORARY_REDIRECT)
                                .body(Either::Right(Empty::new()))
                                .unwrap();
                        };
                    };
                }
            }
        }
    }
    debug!("404 https://{server_name}/api/otp{path}");
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Either::Right(Empty::new()))
        .unwrap()
}

async fn validate_otp(token: &str, store_cache: &Arc<NonEmptyPinboard<Snapshot>>) -> Option<User> {
    let key = format!("otp/{token}");
    let otp = store_cache.get_ref().get::<Otp>(key.as_str())?;
    let _ = Snapshot::delete([key.as_str()].iter()).await;
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let elapsed = timestamp - otp.timestamp;
    if otp.timestamp > timestamp || elapsed > OTP_VALIDITY_DURATION {
        None
    } else {
        let key = format!("acc/{}", otp.user_id);
        let user = store_cache.get_ref().get(key.as_str())?;
        Some(user)
    }
}

fn single<T>(mut iter: impl Iterator<Item = T>) -> Option<T> {
    iter.next().filter(|_| iter.next().is_none())
}
