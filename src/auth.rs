use crate::session::SessionState;
use crate::store::Snapshot;
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
use std::ops::Deref;
use std::sync::Arc;

#[derive(Serialize)]
struct AllowCredentials {
    id: String,
    #[serde(rename = "type")]
    typ: &'static str,
}

impl AllowCredentials {
    pub fn from_id(id: String) -> Self {
        Self {
            id,
            typ: "public-key",
        }
    }
}

#[derive(Serialize)]
struct CredentialCreationOptions {
    challenge: String,
}

#[derive(Serialize)]
struct CredentialRequestOptions {
    challenge: String,
    #[serde(rename = "allowCredentials")]
    allow_credentials: Vec<AllowCredentials>,
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
        let mut challenge = [0u8; 32];
        SystemRandom::new().fill(&mut challenge).unwrap();
        let credential_request = CredentialRequestOptions {
            challenge: URL_SAFE_NO_PAD.encode_to_string(challenge),
            allow_credentials: vec![], // todo retrieve passkeys for this user
        };
        return Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, JSON)
            .body(Either::Left(Full::from(
                serde_json::to_vec(&credential_request).unwrap(),
            )))
            .unwrap();
    } else if path == "/credential_request_options" {
        let keys = user
            .map(|user| {
                store_cache
                    .get_ref()
                    .list::<Passkey>(&format!("/pk/{}/{}", user.identification.hash(), user.id))
                    .map(|(_, Passkey { id, .. })| AllowCredentials::from_id(id))
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
        if let Some(user) = user {
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
                            if let Ok(bytes) = field.bytes().await {
                                // c = Some(bytes.deref());
                            }
                        }
                        Some("a") => {
                            if let Ok(bytes) = field.bytes().await {
                                // a = Some(bytes.deref());
                            }
                        }
                        Some("s") => {
                            if let Ok(bytes) = field.bytes().await {
                                // s = Some(bytes.deref());
                            }
                        }
                        Some("u") => {
                            if let Ok(bytes) = field.bytes().await {
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
