use crate::download::download;
use crate::env::ConfigurationKey::{
    StaticGithubBranch, StaticGithubRepository, StaticGithubUser, StaticGithubWebhookToken,
};
use crate::env::secret_value;
use crate::headers::{HSelector, POST, X_HUB_SIGNATURE_256_HASH};
use http_body_util::BodyExt;
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::ALLOW;
use hyper::{Method, Request, Response, StatusCode};
use pinboard::NonEmptyPinboard;
use ring::hmac::{HMAC_SHA256, Key, sign, verify};
use std::sync::Arc;
use tracing::{debug, info, warn};
use zip_static_handler::github::zip_download_branch_url;
use zip_static_handler::handler::Handler;

pub(crate) async fn handle_webhook(
    request: Request<Incoming>,
    handler: Arc<NonEmptyPinboard<Arc<Handler>>>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let mut response = Response::builder();
    let headers = response.headers_mut().unwrap();
    headers.insert(ALLOW, POST);
    if request.method() != Method::POST {
        debug!("405 {}", request.uri().path());
        return response
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Either::Right(Empty::new()))
            .unwrap();
    }
    if let Some(webhook_token) = secret_value(StaticGithubWebhookToken) {
        if let Some(hash) = request
            .headers()
            .get(X_HUB_SIGNATURE_256_HASH)
            .and_then(|it| it.as_bytes().strip_prefix(b"sha256="))
            .and_then(hex_to_bytes)
        {
            let key = Key::new(HMAC_SHA256, webhook_token.as_bytes());
            if let Ok(body) = request.collect().await.map(|it| it.to_bytes()) {
                if verify(&key, body.as_ref(), hash.as_slice()).is_ok() {
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
                                    handler.set(Arc::new(static_handler));
                                    return response
                                        .status(StatusCode::OK)
                                        .body(Either::Right(Empty::new()))
                                        .unwrap();
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
                    return response
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .body(Either::Right(Empty::new()))
                        .unwrap();
                } else {
                    info!(
                        "webhook signature mismatch:\n{hash:x?} != {:x?}",
                        sign(&key, body.as_ref()).as_ref()
                    );
                }
            }
        }
    }
    debug!("403 update webhook");
    response
        .status(StatusCode::FORBIDDEN)
        .body(Either::Right(Empty::new()))
        .unwrap()
}

fn hex_to_bytes(hex: &[u8]) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = vec![];
    for it in hex.chunks(2) {
        let mut b = 0_u8;
        let first = it[0].to_ascii_lowercase();
        if first.is_ascii_digit() {
            b += 0x10 * (first - b'0');
        } else if (b'a'..=b'f').contains(&first) {
            b += 0x10 * (first - b'a' + 10);
        } else {
            return None;
        }
        let second = it[1].to_ascii_lowercase();
        if second.is_ascii_digit() {
            b += second - b'0';
        } else if (b'a'..=b'f').contains(&second) {
            b += second - b'a' + 10;
        } else {
            return None;
        }
        out.push(b);
    }
    Some(out)
}
