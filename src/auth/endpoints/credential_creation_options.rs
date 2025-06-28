use crate::auth::passkey::challenge::ChallengeMetadata;
use crate::auth::passkey::credential_creations_options::{
    CredentialCreationOptions, PubKeyCredParams, Rp, UserId,
};
use crate::auth::passkey::credentials::Credentials;
use crate::auth::passkey::{PassKey, challenge};
use crate::headers::JSON;
use crate::prefix::API_PATH_PREFIX;
use crate::store::Snapshot;
use crate::user::User;
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use tracing::info;

pub(crate) async fn post(
    request: Request<Incoming>,
    snapshot: &Arc<Snapshot>,
    user: User,
) -> Option<Response<Either<Full<Bytes>, Empty<Bytes>>>> {
    if let Some(challenge) = request
        .collect()
        .await
        .map(|it| it.to_bytes())
        .ok()
        .and_then(|body| serde_json::from_slice::<ChallengeMetadata>(body.as_ref()).ok())
        .and_then(|metadata| challenge::new(&metadata))
    {
        let keys = snapshot
            .list::<PassKey>(&format!("pk/{}/", user.id))
            .map(|(_, key)| Credentials::from_id(key.id))
            .collect::<Vec<_>>();
        let credential_creation = CredentialCreationOptions {
            challenge: URL_SAFE_NO_PAD.encode_to_string(challenge),
            exclude_credentials: keys,
            pub_key_cred_params: vec![
                PubKeyCredParams::ed25519(),
                PubKeyCredParams::es256(),
                PubKeyCredParams::rs256(),
            ],
            rp: Rp::default(),
            user: UserId::from(&user),
        };
        info!(
            "200 {}/auth/credential_creation_options",
            API_PATH_PREFIX.without_trailing_slash
        );
        Some(
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, JSON)
                .body(Either::Left(Full::from(
                    serde_json::to_vec(&credential_creation).unwrap(),
                )))
                .unwrap(),
        )
    } else {
        None
    }
}
