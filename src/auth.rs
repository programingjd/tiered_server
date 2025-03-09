use crate::session::SessionState;
use crate::store::Snapshot;
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::http::HeaderValue;
use hyper::{Request, Response, StatusCode};
use pinboard::NonEmptyPinboard;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
struct AllowCredentials {
    id: String,
    #[serde(rename = "type")]
    typ: String,
}

#[derive(Serialize)]
struct CredentialRequestOptions {
    challenge: String,
    #[serde(rename = "allowCredentials")]
    allow_credentials: Vec<AllowCredentials>,
}

const JSON: HeaderValue = HeaderValue::from_static("application/json");

pub(crate) async fn handle_api_auth(
    request: Request<Incoming>,
    store_cache: Arc<NonEmptyPinboard<Snapshot>>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = &request.uri().path()[9..];
    if let SessionState::Valid { user: _user } =
        SessionState::from_headers(request.headers(), store_cache).await
    {
        if path == "/credential_creation_options" {
            let mut challenge = [0u8; 32];
            SystemRandom::new().fill(&mut challenge).unwrap();
            let credential_request = CredentialRequestOptions {
                challenge: URL_SAFE_NO_PAD.encode_to_string(challenge),
                allow_credentials: vec![], // todo retrieve passkeys for this user
            };
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(CONTENT_TYPE, JSON)
                .body(Either::Left(Full::from(
                    serde_json::to_vec(&credential_request).unwrap(),
                )))
                .unwrap();
        }
    }
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Either::Right(Empty::new()))
        .unwrap()
}
