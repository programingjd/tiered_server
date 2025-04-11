use crate::env::ConfigurationKey::ChallengeSigningKey;
use crate::env::secret_value;
use crate::headers::{GET, HEAD, POST};
use crate::rsa::rsa_spki_der;
use crate::server::{DOMAIN_APEX, DOMAIN_TITLE};
use crate::session::{DELETE_SID_COOKIES, DELETE_ST_COOKIES, SID_EXPIRED, SessionState};
use crate::store::Snapshot;
use crate::user::User;
use base64_simd::URL_SAFE_NO_PAD;
use coset::iana::{
    Algorithm, Ec2KeyParameter, EllipticCurve, EnumI64, KeyType, OkpKeyParameter, RsaKeyParameter,
};
use coset::{CborSerializable, CoseKey, Label, RegisteredLabel, RegisteredLabelWithPrivate};
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ALLOW, CONTENT_TYPE, SET_COOKIE};
use hyper::http::HeaderValue;
use hyper::{Method, Request, Response, StatusCode};
use multer::{Constraints, Multipart, SizeLimit, parse_boundary};
use pinboard::NonEmptyPinboard;
use ring::digest::{SHA256, digest};
use ring::hmac::{HMAC_SHA256, Key, Tag, sign};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature;
use ring::signature::{ECDSA_P256_SHA256_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;

//noinspection SpellCheckingInspection
static SIGNING_KEY: LazyLock<&'static str> = LazyLock::new(|| {
    secret_value(ChallengeSigningKey).unwrap_or("4nyZsaw5j1JxMy38uIj5sxHucy7Dh_6KTqQWFq2x94g")
});

const CHALLENGE_VALIDITY_DURATION: u32 = 30; // 30 secs

#[derive(Serialize)]
struct Credentials {
    id: String,
    #[serde(rename = "type")]
    typ: &'static str,
}

impl Credentials {
    fn from_id(id: String) -> Self {
        Self {
            id,
            typ: "public-key",
        }
    }
}

#[derive(Serialize)]
struct PubKeyCredParams {
    alg: i16,
    #[serde(rename = "type")]
    typ: &'static str,
}

impl PubKeyCredParams {
    fn ed25519() -> Self {
        Self {
            alg: -8,
            typ: "public-key",
        }
    }
    fn es256() -> Self {
        Self {
            alg: -7,
            typ: "public-key",
        }
    }
    fn rs256() -> Self {
        Self {
            alg: -257,
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

#[derive(Deserialize)]
struct ClientData<'a> {
    challenge: &'a [u8],
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type")]
enum PassKey {
    ED25519 { id: String, x: String },
    ES256 { id: String, x: String, y: String },
    RS256 { id: String, n: String },
}

impl PassKey {
    fn into_id(self) -> String {
        match self {
            PassKey::ED25519 { id, .. } => id,
            PassKey::ES256 { id, .. } => id,
            PassKey::RS256 { id, .. } => id,
        }
    }
    fn id(&self) -> &str {
        match self {
            PassKey::ED25519 { id, .. } => id.as_str(),
            PassKey::ES256 { id, .. } => id.as_str(),
            PassKey::RS256 { id, .. } => id.as_str(),
        }
    }
    fn ed25519(id: String, bytes: &[u8]) -> Self {
        Self::ED25519 {
            id,
            x: URL_SAFE_NO_PAD.encode_to_string(bytes),
        }
    }
    fn es256(id: String, x: &[u8], y: &[u8]) -> Self {
        Self::ES256 {
            id,
            x: URL_SAFE_NO_PAD.encode_to_string(x),
            y: URL_SAFE_NO_PAD.encode_to_string(y),
        }
    }
    fn rsa256(id: String, bytes: &[u8]) -> Self {
        Self::RS256 {
            id,
            n: URL_SAFE_NO_PAD.encode_to_string(bytes),
        }
    }
    fn verify(&self, signature: &[u8], authenticator_data: &[u8], client_data_hash: &[u8]) -> bool {
        match self {
            PassKey::ED25519 { x, .. } => {
                if let Ok(x) = URL_SAFE_NO_PAD.decode_to_vec(x) {
                    let public_key = signature::UnparsedPublicKey::new(&ED25519, x);
                    let mut payload =
                        Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
                    payload.extend(authenticator_data.iter());
                    payload.extend(client_data_hash.iter());
                    return public_key.verify(&payload, signature).is_ok();
                };
            }
            PassKey::ES256 { x, y, .. } => {
                if let Ok(x) = URL_SAFE_NO_PAD.decode_to_vec(x) {
                    if let Ok(y) = URL_SAFE_NO_PAD.decode_to_vec(y) {
                        let mut public_key_sec1 = [0u8; 65];
                        public_key_sec1[0] = 0x04;
                        public_key_sec1[1..33].copy_from_slice(&x);
                        public_key_sec1[33..].copy_from_slice(&y);
                        let key = signature::UnparsedPublicKey::new(
                            &ECDSA_P256_SHA256_ASN1,
                            public_key_sec1,
                        );

                        let mut payload =
                            Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
                        payload.extend(authenticator_data.iter());
                        payload.extend(client_data_hash.iter());
                        return key.verify(&payload, signature).is_ok();
                    }
                };
            }
            PassKey::RS256 { n, .. } => {
                if let Ok(n) = URL_SAFE_NO_PAD.decode_to_vec(n) {
                    if let Some(public_key_der) = rsa_spki_der(&n) {
                        let public_key = signature::UnparsedPublicKey::new(
                            &RSA_PKCS1_2048_8192_SHA256,
                            public_key_der,
                        );
                        let mut payload =
                            Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
                        payload.extend(authenticator_data.iter());
                        payload.extend(client_data_hash.iter());
                        return public_key.verify(&payload, signature).is_ok();
                    }
                };
            }
        }
        false
    }
    fn new(id: String, alg: i16, cose: &[u8]) -> Option<Self> {
        match alg {
            -8 | -7 | -257 => {}
            _ => return None,
        }
        let key = CoseKey::from_slice(cose).ok()?;
        if let (RegisteredLabel::Assigned(key_type), RegisteredLabelWithPrivate::Assigned(alg)) =
            (key.kty, key.alg?)
        {
            match (key_type, alg) {
                (KeyType::OKP, Algorithm::EdDSA) => {
                    let crv: Option<u64> = key.params.iter().find_map(|(k, v)| {
                        if k == &Label::Int(OkpKeyParameter::Crv.to_i64()) {
                            v.as_integer().and_then(|it| it.try_into().ok())
                        } else {
                            None
                        }
                    });
                    if crv == Some(EllipticCurve::Ed25519 as u64) {
                        if let Some(x) = key.params.iter().find_map(|(k, v)| {
                            if k == &Label::Int(OkpKeyParameter::X.to_i64()) {
                                v.as_bytes().map(|it| it.as_slice())
                            } else {
                                None
                            }
                        }) {
                            return Some(PassKey::ed25519(id, x));
                        }
                    }
                }
                (KeyType::EC2, Algorithm::ES256) => {
                    let crv: Option<u64> = key.params.iter().find_map(|(k, v)| {
                        if k == &Label::Int(Ec2KeyParameter::Crv.to_i64()) {
                            v.as_integer().and_then(|it| it.try_into().ok())
                        } else {
                            None
                        }
                    });
                    if crv == Some(EllipticCurve::P_256 as u64) {
                        if let Some(x) = key.params.iter().find_map(|(k, v)| {
                            if k == &Label::Int(Ec2KeyParameter::X.to_i64()) {
                                v.as_bytes().map(|it| it.as_slice())
                            } else {
                                None
                            }
                        }) {
                            if let Some(y) = key.params.iter().find_map(|(k, v)| {
                                if k == &Label::Int(Ec2KeyParameter::Y.to_i64()) {
                                    v.as_bytes().map(|it| it.as_slice())
                                } else {
                                    None
                                }
                            }) {
                                return Some(PassKey::es256(id, x, y));
                            }
                        }
                    }
                }
                (KeyType::RSA, Algorithm::RS256) => {
                    let e: Option<u32> = key.params.iter().find_map(|(k, v)| {
                        if k == &Label::Int(RsaKeyParameter::E.to_i64()) {
                            v.as_bytes().map(|it| {
                                let mut bytes = [0u8; 4];
                                bytes[8 - it.len()..].copy_from_slice(it.as_slice());
                                u32::from_be_bytes(bytes)
                            })
                        } else {
                            None
                        }
                    });
                    if e == Some(65537) {
                        if let Some(n) = key.params.iter().find_map(|(k, v)| {
                            if k == &Label::Int(RsaKeyParameter::N.to_i64()) {
                                v.as_bytes().map(|it| it.as_slice())
                            } else {
                                None
                            }
                        }) {
                            return Some(PassKey::rsa256(id, n));
                        }
                    }
                }
                _ => return None,
            }
        }
        None
    }
}

const JSON: HeaderValue = HeaderValue::from_static("application/json");

fn challenge_signature(challenge: &[u8]) -> Tag {
    let key = Key::new(HMAC_SHA256, SIGNING_KEY.as_bytes());
    sign(&key, challenge)
}

fn new_challenge() -> [u8; 68] {
    let mut challenge = [0u8; 68];
    SystemRandom::new().fill(&mut challenge[..32]).unwrap();
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    challenge[32..36].copy_from_slice(timestamp.to_be_bytes().as_slice());
    let signature = challenge_signature(&challenge[..36]);
    challenge[36..].copy_from_slice(signature.as_ref());
    challenge
}

//noinspection DuplicatedCode
pub(crate) async fn handle_auth(
    request: Request<Incoming>,
    store_cache: Arc<NonEmptyPinboard<Snapshot>>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = &request.uri().path()[9..];
    let method = request.method();
    let session_state = SessionState::from_headers(request.headers(), &store_cache).await;
    let (user, session) = match session_state {
        SessionState::Valid { user, session } => (Some(user), Some(session)),
        SessionState::Expired { user } => (Some(user), None),
        _ => (None, None),
    };
    if path == "/credential_request_options" {
        if method != Method::GET {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, GET);
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        // let keys = user
        //     .map(|user| {
        //         store_cache
        //             .get_ref()
        //             .list::<PassKey>(&format!("/pk/{}/", user.id))
        //             .map(|(_, key)| Credentials::from_id(key.into_id()))
        //             .collect::<Vec<_>>()
        //     })
        //     .unwrap_or(vec![]);
        let challenge = new_challenge();
        let credential_create = CredentialRequestOptions {
            challenge: URL_SAFE_NO_PAD.encode_to_string(challenge),
            // allow_credentials: keys,
            allow_credentials: vec![],
        };
        return Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, JSON)
            .body(Either::Left(Full::from(
                serde_json::to_vec(&credential_create).unwrap(),
            )))
            .unwrap();
    } else if path == "/credentials" {
        if let Some(user) = user {
            if method != Method::HEAD {
                let mut response = Response::builder();
                let headers = response.headers_mut().unwrap();
                headers.insert(ALLOW, HEAD);
                return response
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Either::Right(Empty::new()))
                    .unwrap();
            }
            return if store_cache
                .get_ref()
                .list::<PassKey>(&format!("acc/{}/", user.id))
                .next()
                .is_some()
            {
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Either::Right(Empty::new()))
                    .unwrap()
            } else {
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Either::Right(Empty::new()))
                    .unwrap()
            };
        }
    } else if path == "/credential_creation_options" {
        if let Some(user) = user {
            if method != Method::GET {
                let mut response = Response::builder();
                let headers = response.headers_mut().unwrap();
                headers.insert(ALLOW, GET);
                return response
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Either::Right(Empty::new()))
                    .unwrap();
            }
            let keys = store_cache
                .get_ref()
                .list::<PassKey>(&format!("pk/{}/", user.id))
                .map(|(_, key)| Credentials::from_id(key.into_id()))
                .collect::<Vec<_>>();
            let challenge = new_challenge();
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
            return Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, JSON)
                .body(Either::Left(Full::from(
                    serde_json::to_vec(&credential_creation).unwrap(),
                )))
                .unwrap();
        }
    } else if path == "/record_credential" {
        if let Some(user) = user {
            if request.method() != Method::POST {
                let mut response = Response::builder();
                let headers = response.headers_mut().unwrap();
                headers.insert(ALLOW, POST);
                return response
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Either::Right(Empty::new()))
                    .unwrap();
            }
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
                let mut i = None;
                let mut a = 0_i16;
                let mut k = vec![];
                let mut challenge_verified = false;
                while let Ok(Some(field)) = multipart.next_field().await {
                    match field.name() {
                        Some("i") => {
                            if let Ok(it) = field.bytes().await {
                                i = Some(URL_SAFE_NO_PAD.encode_to_string(it.as_ref()));
                            }
                        }
                        Some("a") => {
                            if let Ok(it) = field.text().await {
                                if let Ok(it) = it.parse::<i16>() {
                                    a = it;
                                }
                            }
                        }
                        Some("k") => {
                            if let Ok(it) = field.bytes().await {
                                k.extend(it.as_ref().iter());
                            }
                        }
                        Some("c") => {
                            if let Ok(it) = field.bytes().await {
                                if let Ok(client_data) =
                                    serde_json::from_slice::<ClientData>(it.as_ref())
                                {
                                    let challenge = client_data.challenge;
                                    if challenge.len() == 68 {
                                        let timestamp: [u8; 4] =
                                            challenge[32..36].try_into().unwrap();
                                        let timestamp = u32::from_be_bytes(timestamp);
                                        let now = SystemTime::now()
                                            .duration_since(SystemTime::UNIX_EPOCH)
                                            .unwrap()
                                            .as_secs()
                                            as u32;
                                        let elapsed = now - timestamp;
                                        if timestamp > now || elapsed > CHALLENGE_VALIDITY_DURATION
                                        {
                                            let signature = challenge_signature(&challenge[..36]);
                                            if signature.as_ref() == &challenge[36..] {
                                                challenge_verified = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if i.is_some() && challenge_verified {
                    if let Some(passkey) = PassKey::new(i.unwrap(), a, k.as_slice()) {
                        if Snapshot::set(&format!("pk/{}/{}", user.id, passkey.id()), &passkey)
                            .await
                            .is_some()
                        {
                            return Response::builder()
                                .status(StatusCode::OK)
                                .body(Either::Right(Empty::new()))
                                .unwrap();
                        }
                    }
                }
            }
        }
    } else if path == "/validate_credential" {
        if request.method() != Method::POST {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, POST);
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
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
            let mut i = None;
            let mut s = vec![];
            let mut u = None;
            let mut d = vec![];
            let mut hash = None;
            while let Ok(Some(field)) = multipart.next_field().await {
                match field.name() {
                    Some("i") => {
                        if let Ok(it) = field.bytes().await {
                            i = Some(URL_SAFE_NO_PAD.encode_to_string(it.as_ref()));
                        }
                    }
                    Some("s") => {
                        if let Ok(it) = field.bytes().await {
                            s.extend(it.as_ref().iter());
                        }
                    }
                    Some("u") => {
                        if let Ok(it) = field.bytes().await {
                            u = Some(URL_SAFE_NO_PAD.encode_to_string(it.as_ref()));
                        }
                    }
                    Some("c") => {
                        if let Ok(it) = field.bytes().await {
                            if let Ok(client_data) =
                                serde_json::from_slice::<ClientData>(it.as_ref())
                            {
                                let challenge = client_data.challenge;
                                if challenge.len() == 68 {
                                    let timestamp: [u8; 4] = challenge[32..36].try_into().unwrap();
                                    let timestamp = u32::from_be_bytes(timestamp);
                                    let now = SystemTime::now()
                                        .duration_since(SystemTime::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs()
                                        as u32;
                                    let elapsed = now - timestamp;
                                    if timestamp > now || elapsed > CHALLENGE_VALIDITY_DURATION {
                                        let signature = challenge_signature(&challenge[..36]);
                                        if signature.as_ref() == &challenge[36..] {
                                            hash = Some(
                                                digest(&SHA256, it.as_ref()).as_ref().to_vec(),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Some("d") => {
                        if let Ok(it) = field.bytes().await {
                            d.extend(it.as_ref().iter());
                        }
                    }
                    _ => {}
                }
            }
            if i.is_some()
                && u.is_some()
                && hash.is_some()
                && s.is_empty()
                && d.is_empty()
                && digest(&SHA256, DOMAIN_APEX.as_bytes()).as_ref() == &d[..32]
            {
                let passkey_id = i.unwrap();
                let user_id = u.unwrap();
                if store_cache
                    .get_ref()
                    .get::<PassKey>(&format!("pk/{user_id}/{passkey_id}"))
                    .filter(|passkey| {
                        passkey.verify(s.as_slice(), d.as_slice(), hash.unwrap().as_slice())
                    })
                    .is_some()
                {
                    if let Some(session) = User::create_session(user_id).await {
                        let mut response = Response::builder().status(StatusCode::OK);
                        let headers = response.headers_mut().unwrap();
                        session.cookies().into_iter().for_each(|cookie| {
                            headers.append(SET_COOKIE, cookie);
                        });
                        return response.body(Either::Right(Empty::new())).unwrap();
                    };
                }
            }
        }
    } else if path == "/forget_user" {
        if request.method() != Method::GET {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, GET);
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        if user.is_some() {
            if let Some(session) = session {
                Snapshot::delete([format!("sid/{}", session.id)].iter()).await;
            }
            let mut response = Response::builder().status(StatusCode::OK);
            let headers = response.headers_mut().unwrap();
            headers.append(SET_COOKIE, DELETE_ST_COOKIES);
            headers.append(SET_COOKIE, DELETE_SID_COOKIES);
            return response.body(Either::Right(Empty::new())).unwrap();
        }
    } else if path == "/disconnect_user" {
        if request.method() != Method::GET {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, GET);
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        if user.is_some() {
            if let Some(mut session) = session {
                session.timestamp = 0;
                Snapshot::set(&format!("sid/{}", session.id), &session).await;
            }
            let mut response = Response::builder().status(StatusCode::OK);
            let headers = response.headers_mut().unwrap();
            headers.append(SET_COOKIE, SID_EXPIRED);
            return response.body(Either::Right(Empty::new())).unwrap();
        }
    }
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Either::Right(Empty::new()))
        .unwrap()
}
