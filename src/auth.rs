use crate::DOMAIN_TITLE;
use crate::session::SessionState;
use crate::store::Snapshot;
use crate::user::{IdentificationMethod, User};
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::http::HeaderValue;
use hyper::{Request, Response, StatusCode};
use multer::{Constraints, Multipart, SizeLimit, parse_boundary};
use pinboard::NonEmptyPinboard;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize)]
struct Credentials {
    id: String,
    #[serde(rename = "type")]
    typ: &'static str,
}

impl Credentials {
    pub fn from_id(id: String) -> Self {
        Self {
            id,
            typ: "public-key",
        }
    }
}

#[derive(Serialize)]
struct PubKeyCredParams {
    alg: i8,
    #[serde(rename = "type")]
    typ: &'static str,
}

impl PubKeyCredParams {
    pub fn ed25519() -> Self {
        Self {
            alg: -8,
            typ: "public-key",
        }
    }
}

#[derive(Serialize)]
struct Rp {
    name: &'static str,
}

impl Default for Rp {
    fn default() -> Self {
        Self {
            name: *DOMAIN_TITLE,
        }
    }
}

#[derive(Serialize)]
struct UserId {
    id: String,
    display_name: String,
    name: String,
}

impl From<&User> for UserId {
    fn from(user: &User) -> Self {
        Self {
            id: user.id.clone(),
            display_name: user.first_name.clone(),
            name: format!("{} {}", user.first_name, user.last_name),
        }
    }
}

#[derive(Serialize)]
struct CredentialCreationOptions {
    challenge: String,
    #[serde(rename = "excludeCredentials")]
    exclude_credentials: Vec<Credentials>,
    #[serde(rename = "pubKeyCredParams")]
    pub_key_cred_params: Vec<PubKeyCredParams>,
    rp: Rp,
    user: UserId,
}

#[derive(Serialize)]
struct CredentialRequestOptions {
    challenge: String,
    #[serde(rename = "allowCredentials")]
    allow_credentials: Vec<Credentials>,
}

#[derive(Serialize, Deserialize)]
struct Passkey {
    id: String,
}

const JSON: HeaderValue = HeaderValue::from_static("application/json");

pub(crate) async fn handle_auth(
    request: Request<Incoming>,
    store_cache: Arc<NonEmptyPinboard<Snapshot>>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = &request.uri().path()[9..];
    let user = match SessionState::from_headers(request.headers(), &store_cache).await {
        SessionState::Valid { user } => Some(user),
        SessionState::Expired { user } => Some(user),
        _ => None,
    };
    if path == "/credential_creation_options" {
        if let Some(boundary) = request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|it| it.to_str().ok())
            .and_then(|it| parse_boundary(it).ok())
        {
            let mut multipart = Multipart::with_constraints(
                request.into_body().into_data_stream(),
                boundary,
                Constraints::new().size_limit(SizeLimit::new().whole_stream(1024)),
            );
            let mut email = None;
            let mut first_name = None;
            while let Ok(Some(field)) = multipart.next_field().await {
                match field.name() {
                    Some("email") => {
                        if let Ok(it) = field.text().await {
                            email = Some(it)
                        }
                    }
                    Some("first_name") => {
                        if let Ok(it) = field.text().await {
                            first_name = Some(it)
                        }
                    }
                    _ => {}
                }
            }
            if let Some(email) = email {
                let identification = IdentificationMethod::Email(email);
                let prefix = format!("/pk/{}/", identification.hash());
                let cache = store_cache.get_ref();
                let mut users = cache.list::<User>(&prefix).filter_map(|(_id, ref user)| {
                    if first_name.is_none() || first_name.as_deref() == Some(&user.first_name) {
                        Some(user.clone())
                    } else {
                        None
                    }
                });
                if let Some(user) = users.next() {
                    if users.next().is_none() {
                        let keys = store_cache
                            .get_ref()
                            .list::<Passkey>(&format!("{}{}/", prefix, user.id))
                            .map(|(_, Passkey { id, .. })| Credentials::from_id(id))
                            .collect::<Vec<_>>();
                        let mut challenge = [0u8; 32];
                        SystemRandom::new().fill(&mut challenge).unwrap();
                        let credential_creation = CredentialCreationOptions {
                            challenge: URL_SAFE_NO_PAD.encode_to_string(challenge),
                            exclude_credentials: keys,
                            pub_key_cred_params: vec![PubKeyCredParams::ed25519()],
                            rp: Rp::default(),
                            user: UserId::from(&user),
                        };
                        return Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, JSON)
                            .body(Either::Left(Full::from(
                                serde_json::to_vec(&credential_creation).unwrap(),
                            )))
                            .unwrap();
                    }
                }
            }
        }
    } else if path == "/credential_request_options" {
        let keys = user
            .map(|user| {
                store_cache
                    .get_ref()
                    .list::<Passkey>(&format!("/pk/{}/{}/", user.identification.hash(), user.id))
                    .map(|(_, Passkey { id, .. })| Credentials::from_id(id))
                    .collect::<Vec<_>>()
            })
            .unwrap_or(vec![]);

        let mut challenge = [0u8; 32];
        SystemRandom::new().fill(&mut challenge).unwrap();
        let credential_create = CredentialRequestOptions {
            challenge: URL_SAFE_NO_PAD.encode_to_string(challenge),
            allow_credentials: keys,
        };
        return Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, JSON)
            .body(Either::Left(Full::from(
                serde_json::to_vec(&credential_create).unwrap(),
            )))
            .unwrap();
    } else if path == "/validate" {
        if let Some(_user) = user {
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
                // let mut c = None;
                // let mut a = None;
                // let mut s = None;
                // let mut u = None;
                while let Ok(Some(field)) = multipart.next_field().await {
                    match field.name() {
                        Some("c") => {
                            if let Ok(_bytes) = field.bytes().await {
                                // c = Some(bytes.deref());
                            }
                        }
                        Some("a") => {
                            if let Ok(_bytes) = field.bytes().await {
                                // a = Some(bytes.deref());
                            }
                        }
                        Some("s") => {
                            if let Ok(_bytes) = field.bytes().await {
                                // s = Some(bytes.deref());
                            }
                        }
                        Some("u") => {
                            if let Ok(_bytes) = field.bytes().await {
                                // u = Some(bytes.deref());
                            }
                        }
                        _ => {}
                    }
                }
                // if c.is_some() && a.is_some() && s.is_some() {
                // let c = c.unwrap();
                // let a = a.unwrap();
                // let s = s.unwrap();
                // }
            }
        }
    }
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Either::Right(Empty::new()))
        .unwrap()
}
