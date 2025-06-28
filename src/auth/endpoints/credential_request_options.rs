use crate::auth::passkey::challenge;
use crate::auth::passkey::challenge::ChallengeMetadata;
use crate::auth::passkey::credential_request_options::CredentialRequestOptions;
use crate::headers::JSON;
use crate::prefix::API_PATH_PREFIX;
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::{Request, Response, StatusCode};
use tracing::info;

pub(crate) async fn post(
    request: Request<Incoming>,
) -> Option<Response<Either<Full<Bytes>, Empty<Bytes>>>> {
    if let Some(challenge) = request
        .collect()
        .await
        .map(|it| it.to_bytes())
        .ok()
        .and_then(|body| serde_json::from_slice::<ChallengeMetadata>(body.as_ref()).ok())
        .and_then(|metadata| challenge::new(&metadata))
    {
        // let keys = user
        //     .map(|user| {
        //         store_cache
        //             .get_ref()
        //             .list::<PassKey>(&format!("/pk/{}/", user.id))
        //             .map(|(_, key)| Credentials::from_id(key.into_id()))
        //             .collect::<Vec<_>>()
        //     })
        //     .unwrap_or(vec![]);
        let credential_create = CredentialRequestOptions {
            challenge: URL_SAFE_NO_PAD.encode_to_string(challenge),
            // allow_credentials: keys,
            allow_credentials: vec![],
        };
        info!(
            "200 {}/auth/credential_request_options",
            API_PATH_PREFIX.without_trailing_slash
        );
        Some(
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, JSON)
                .body(Either::Left(Full::from(
                    serde_json::to_vec(&credential_create).unwrap(),
                )))
                .unwrap(),
        )
    } else {
        None
    }
}
