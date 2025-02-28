use crate::env::ConfigurationKey::OtpSigningKey;
use crate::env::secret_value;
use crate::headers::{CLOUDFLARE_CDN_CACHE_CONTROL, GET};
use crate::store::get_otp;
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ALLOW, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use ring::hmac::{HMAC_SHA256, Key, sign};
use serde::{Deserialize, Serialize};
use std::str::from_utf8;
use std::sync::LazyLock;

//noinspection SpellCheckingInspection
static SIGNING_KEY: LazyLock<&'static str> = LazyLock::new(|| {
    secret_value(OtpSigningKey).unwrap_or("A8UVAbg0L_ZCsirPCsdxqe5GmaFRa1NSfUkc3Evsu2k")
});

#[derive(Serialize, Deserialize)]
pub(crate) enum ValidationMethod {
    Email(String),
}

pub(crate) fn token_signature(token: &str) -> Option<String> {
    let payload = URL_SAFE_NO_PAD.decode_to_vec(token).ok()?;
    let key = Key::new(HMAC_SHA256, SIGNING_KEY.as_bytes());
    Some(URL_SAFE_NO_PAD.encode_to_string(sign(&key, &payload).as_ref()))
}

pub(crate) async fn handle_otp(
    request: Request<Incoming>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = request.uri().path();
    if request.method() != Method::GET {
        let mut response = Response::builder();
        let headers = response.headers_mut().unwrap();
        headers.insert(ALLOW, GET);
        return response
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Either::Right(Empty::new()))
            .unwrap();
    }
    let payload = &path[9..]; // /api/otp/{payload}
    let mut iter = payload.split('.');
    let token = iter.next();
    let signature = iter.next();
    if let Some(signature) = signature {
        let token = token.unwrap();
        if let Some(signed) = token_signature(token) {
            if signed.as_str() == signature {
                if let Some(_validation_method) = get_otp(token).await {
                    todo!("redirect to passkey creation page")
                };
            }
        }
    }
    let mut response = Response::builder();
    let headers = response.headers_mut().unwrap();
    //noinspection SpellCheckingInspection
    headers.insert(
        from_utf8(CLOUDFLARE_CDN_CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("public,max-age=31536000,s-maxage=31536000,immutable"),
    );
    response
        .status(StatusCode::NOT_FOUND)
        .body(Either::Right(Empty::new()))
        .unwrap()
}
