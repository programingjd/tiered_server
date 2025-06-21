use crate::download::download;
use crate::env::ConfigurationKey::{
    StaticGithubBranch, StaticGithubRepository, StaticGithubUser, StaticGithubWebhookToken,
};
use crate::env::secret_value;
use crate::handler::set;
use crate::headers::{HSelector, POST, X_HUB_SIGNATURE_256_HASH};
use crate::hex::{bytes_to_hex, hex_to_bytes};
use http_body_util::BodyExt;
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::ALLOW;
use hyper::{Method, Request, Response, StatusCode};
use ring::hmac::{HMAC_SHA256, Key, sign, verify};
use tracing::{info, warn};
use zip_static_handler::github::zip_download_branch_url;
use zip_static_handler::handler::Handler;

pub(crate) async fn handle_webhook(
    request: Request<Incoming>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let mut response = Response::builder();
    let headers = response.headers_mut().unwrap();
    headers.insert(ALLOW, POST);
    if request.method() != Method::POST {
        info!("405 {}", request.uri().path());
        return response
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Either::Right(Empty::new()))
            .unwrap();
    }
    if let Some(webhook_token) = secret_value(StaticGithubWebhookToken) {
        if let Some(hash_hex) = request
            .headers()
            .get(X_HUB_SIGNATURE_256_HASH)
            .and_then(|it| it.as_bytes().strip_prefix(b"sha256="))
        {
            let hash_hex = hash_hex.to_vec();
            let hash_bytes = match hex_to_bytes(&hash_hex, Vec::with_capacity(32)) {
                Some(it) => it,
                None => {
                    warn!("invalid hash");
                    return response
                        .status(StatusCode::BAD_REQUEST)
                        .body(Either::Right(Empty::new()))
                        .unwrap();
                }
            };
            let key = Key::new(HMAC_SHA256, webhook_token.as_bytes());
            if let Ok(body) = request.collect().await.map(|it| it.to_bytes()) {
                if verify(&key, body.as_ref(), hash_bytes.as_slice()).is_ok() {
                    if update().await.is_some() {
                        info!("204 update webhook");
                        return response
                            .status(StatusCode::NO_CONTENT)
                            .body(Either::Right(Empty::new()))
                            .unwrap();
                    }
                    info!("503 update webhook");
                    return response
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .body(Either::Right(Empty::new()))
                        .unwrap();
                } else {
                    info!(
                        "webhook signature mismatch:\n{} != {}",
                        hash_hex.escape_ascii(),
                        bytes_to_hex(sign(&key, body.as_ref()).as_ref())
                    );
                }
            }
        }
    }
    info!("403 update webhook");
    response
        .status(StatusCode::FORBIDDEN)
        .body(Either::Right(Empty::new()))
        .unwrap()
}

pub(crate) async fn handle_local_update_request() -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let response = Response::builder();
    if update().await.is_some() {
        info!("204 update webhook");
        response
            .status(StatusCode::NO_CONTENT)
            .body(Either::Right(Empty::new()))
            .unwrap()
    } else {
        info!("503 update webhook");
        response
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Either::Right(Empty::new()))
            .unwrap()
    }
}

async fn update() -> Option<()> {
    let github_user = secret_value(StaticGithubUser).unwrap();
    let github_repository = secret_value(StaticGithubRepository).unwrap();
    let github_branch = secret_value(StaticGithubBranch).unwrap();
    match download(&zip_download_branch_url(
        github_user,
        github_repository,
        github_branch,
    ))
    .await
    {
        Ok(zip) => {
            match Handler::builder()
                .with_custom_header_selector(&HSelector)
                .with_zip_prefix(format!("{github_repository}-{github_branch}/"))
                .with_zip(zip)
                .try_build()
            {
                Ok(static_handler) => {
                    set(static_handler);
                    return Some(());
                }
                Err(err) => {
                    warn!("failed to update static content: {err}");
                }
            }
        }
        Err(err) => {
            warn!("failed to download static content: {err}");
        }
    }
    None
}
