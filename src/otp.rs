use crate::env::ConfigurationKey::OtpSigningKey;
use crate::env::secret_value;
use crate::headers::{CLOUDFLARE_CDN_CACHE_CONTROL, GET};
use crate::store::Snapshot;
use crate::user::{IdentificationMethod, User};
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ALLOW, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use pinboard::NonEmptyPinboard;
use ring::hmac::{HMAC_SHA256, Key, sign};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::str::from_utf8;
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;

//noinspection SpellCheckingInspection
static SIGNING_KEY: LazyLock<&'static str> = LazyLock::new(|| {
    secret_value(OtpSigningKey).unwrap_or("A8UVAbg0L_ZCsirPCsdxqe5GmaFRa1NSfUkc3Evsu2k")
});

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Otp {
    id: String,
    user_id: String,
    identity_hash: String,
    timestamp: u32,
}

impl Otp {
    pub(crate) async fn send(user: &User, snapshot: &Snapshot) -> Option<()> {
        let email = match &user.identification {
            IdentificationMethod::Email(email) => email.as_str(),
            _ => return None,
        };
        let otp = Self::create(user, snapshot).await?;
        let id = otp.id.as_str();
        let signature = token_signature(id).expect("token should be url safe base64 encoded");
        let url = format!("/api/otp/{id}.{signature}");
        todo!()
    }
    async fn create(user: &User, snapshot: &Snapshot) -> Option<Self> {
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
        let key = format!("/otp/{id}");
        let otp = Self {
            id,
            user_id: user.id.clone(),
            identity_hash: user.identification.hash(),
            timestamp,
        };
        let _ = Self::remove_expired(snapshot, Some(user.id.as_str())).await;
        Snapshot::set(key.as_str(), &otp).await?;
        Some(otp)
    }
    async fn remove_expired(snapshot: &Snapshot, user_id: Option<&str>) -> Option<()> {
        todo!()
    }
}

pub(crate) fn token_signature(token: &str) -> Option<String> {
    let payload = URL_SAFE_NO_PAD.decode_to_vec(token).ok()?;
    let key = Key::new(HMAC_SHA256, SIGNING_KEY.as_bytes());
    Some(URL_SAFE_NO_PAD.encode_to_string(sign(&key, &payload).as_ref()))
}

pub(crate) async fn handle_otp(
    request: Request<Incoming>,
    store_cache: Arc<NonEmptyPinboard<Snapshot>>,
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
                if let Some(user) = validate_otp(token, store_cache).await {
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

const OTP_VALIDITY_DURATION: u32 = 1_200; // 20 mins

async fn validate_otp(token: &str, snapshot: Arc<NonEmptyPinboard<Snapshot>>) -> Option<User> {
    let key = format!("/otp/{token}");
    let otp = snapshot.get_ref().get::<Otp>(key.as_str())?;
    let _ = Snapshot::delete(vec![key.as_str()]).await;
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let elapsed = timestamp - otp.timestamp;
    if otp.timestamp > timestamp || elapsed > OTP_VALIDITY_DURATION {
        None
    } else {
        let key = format!("/pk/{}/{}", otp.identity_hash, otp.user_id);
        let user = snapshot.get_ref().get(key.as_str())?;
        Some(user)
    }
}
