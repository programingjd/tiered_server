use crate::env::ConfigurationKey::ChallengeSigningKey;
use crate::env::secret_value;
use crate::headers::{GET, HEAD, JSON, POST};
use crate::hex::hex_to_bytes;
use crate::iter::{pair, single};
use crate::server::DOMAIN_TITLE;
use crate::session::{DELETE_SID_COOKIES, DELETE_ST_COOKIES, SID_EXPIRED, SessionState};
use crate::store::{Snapshot, snapshot};
use crate::user::User;
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{ALLOW, CONTENT_TYPE, LOCATION, SET_COOKIE};
use hyper::http::HeaderValue;
use hyper::{Method, Request, Response, StatusCode};
use multer::{Constraints, Multipart, SizeLimit, parse_boundary};
use ring::digest::{SHA256, digest};
use ring::hmac::{HMAC_SHA256, Key, Tag, sign};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use simple_asn1::{ASN1Block, BigUint, from_der};
use std::fmt::Write;
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;
use tracing::debug;

//noinspection SpellCheckingInspection
static SIGNING_KEY: LazyLock<&'static str> = LazyLock::new(|| {
    secret_value(ChallengeSigningKey).unwrap_or("4nyZsaw5j1JxMy38uIj5sxHucy7Dh_6KTqQWFq2x94g")
});

const CHALLENGE_VALIDITY_DURATION: u32 = 180; // 3 mins

#[derive(Serialize, Deserialize)]
struct ChallengeMetadata {
    uuid: String,
    metadata: Option<Value>,
}

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
    #[serde(rename = "displayName")]
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
struct PassKey {
    id: String,
    subject_public_key_info: String,
}

impl PassKey {
    fn verify(&self, signature: &[u8], authenticator_data: &[u8], client_data_hash: &[u8]) -> bool {
        let subject_public_key_info = URL_SAFE_NO_PAD
            .decode_to_vec(self.subject_public_key_info.clone())
            .unwrap();
        let subject_public_key_info = match from_der(&subject_public_key_info).ok().and_then(single)
        {
            Some(ASN1Block::Sequence(_, blocks)) => blocks,
            _ => {
                debug!("invalid SubjectPublicKeyInfo");
                return false;
            }
        };
        let info = format!("{subject_public_key_info:?}");
        println!("{info}");
        let (algorithm_oid, subject_public_key) = match pair(subject_public_key_info) {
            Some((ASN1Block::Sequence(_, blocks), ASN1Block::BitString(_, _, bytes))) => {
                match blocks.first() {
                    Some(ASN1Block::ObjectIdentifier(_, it)) => {
                        let it = match it.as_vec::<&BigUint>() {
                            Ok(it) => it,
                            Err(_) => {
                                debug!("invalid AlgorithmIdentifier");
                                return false;
                            }
                        };
                        let mut oid = String::with_capacity(it.len() * 5);
                        let mut iter = it.iter();
                        if let Some(first) = iter.next() {
                            let _ = write!(oid, "{}", first);
                        }
                        for it in iter {
                            oid.push('.');
                            let _ = write!(oid, "{}", it);
                        }
                        (oid, bytes)
                    }
                    _ => {
                        debug!("invalid AlgorithmIdentifier");
                        return false;
                    }
                }
            }
            _ => {
                debug!("invalid SubjectPublicKeyInfo");
                return false;
            }
        };
        match algorithm_oid.as_str() {
            "1.3.101.112" => {
                // ED25519
                if subject_public_key.len() != 32 {
                    debug!("invalid ED25519 subject public key");
                    return false;
                }
                let x = &subject_public_key;
                let public_key = signature::UnparsedPublicKey::new(&ED25519, x);
                let mut payload =
                    Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
                payload.extend(authenticator_data.iter());
                payload.extend(client_data_hash.iter());
                public_key.verify(&payload, signature).is_ok()
            }
            "1.2.840.10045.2.1" => {
                // ES256
                let sec1 = &subject_public_key;
                let public_key = signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, sec1);
                let mut payload =
                    Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
                payload.extend(authenticator_data.iter());
                payload.extend(client_data_hash.iter());
                public_key.verify(&payload, signature).is_ok()
            }
            "1.2.840.113549.1.1.1" => {
                // RSA256
                let (n, e) = match from_der(&subject_public_key).ok().and_then(single) {
                    Some(ASN1Block::Sequence(_, blocks)) => match pair(blocks) {
                        Some((ASN1Block::Integer(_, n), ASN1Block::Integer(_, e))) => {
                            let n = match n.to_biguint() {
                                Some(it) => it.to_bytes_be(),
                                None => {
                                    debug!("invalid RSA n value");
                                    return false;
                                }
                            };
                            let e = match e.to_biguint() {
                                Some(it) => it.to_bytes_be(),
                                None => {
                                    debug!("invalid RSA e value");
                                    return false;
                                }
                            };
                            (n, e)
                        }
                        _ => {
                            debug!("invalid RSA subject public key");
                            return false;
                        }
                    },
                    _ => {
                        debug!("invalid RSA subject public key");
                        return false;
                    }
                };
                let public_key = RsaPublicKeyComponents { n, e };
                // let public_key = signature::UnparsedPublicKey::new(
                //     &RSA_PKCS1_2048_8192_SHA256,
                //     subject_public_key,
                // );
                let mut payload =
                    Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
                payload.extend(authenticator_data.iter());
                payload.extend(client_data_hash.iter());
                public_key
                    .verify(&RSA_PKCS1_2048_8192_SHA256, &payload, signature)
                    .is_ok()
            }
            _ => {
                debug!("invalid algorithm OID");
                false
            }
        }
    }
    fn new(id: String, alg: i16, subject_public_key_info: Vec<u8>) -> Option<Self> {
        match alg {
            -8 => debug!("ED25519"),
            -7 => debug!("ES256"),
            -257 => debug!("RS256"),
            it => {
                debug!("Unsupported algorithm: {it}");
                return None;
            }
        }
        Some(Self {
            id,
            subject_public_key_info: URL_SAFE_NO_PAD.encode_to_string(&subject_public_key_info),
        })
    }
}

fn challenge_signature(challenge: &[u8]) -> Tag {
    let key = Key::new(HMAC_SHA256, SIGNING_KEY.as_bytes());
    sign(&key, challenge)
}

fn new_challenge(challenge_metadata: &ChallengeMetadata) -> Option<Vec<u8>> {
    let mut challenge = Vec::with_capacity(1024);
    let mut part_count = 0_usize;
    for (i, it) in challenge_metadata.uuid.split('-').enumerate() {
        part_count += 1;
        match i {
            0 => {
                if it.len() != 8 {
                    return None;
                } else {
                    challenge = hex_to_bytes(it.as_bytes(), challenge)?;
                }
            }
            1..=3 => {
                if it.len() != 4 {
                    return None;
                } else {
                    challenge = hex_to_bytes(it.as_bytes(), challenge)?;
                }
            }
            4 => {
                if it.len() != 12 {
                    return None;
                } else {
                    challenge = hex_to_bytes(it.as_bytes(), challenge)?;
                }
            }
            _ => return None,
        }
    }
    if part_count != 5 {
        return None;
    }
    challenge.push(0);
    challenge.push(0);
    if let Some(ref metadata) = challenge_metadata.metadata {
        serde_json::to_writer(&mut challenge, metadata).ok()?;
    }
    let len = challenge.len();
    // 16 (uuid) + 2 (json len) + len (json) + 32 (random) + 4 (timestamp) + 32 (signature) = 86 + len
    if len > (u16::MAX - 86) as usize {
        return None;
    }
    let len_bytes = ((len - 18) as u16).to_be_bytes();
    challenge[16] = len_bytes[0];
    challenge[17] = len_bytes[1];
    let mut buf = [0u8; 32];
    SystemRandom::new().fill(&mut buf).unwrap();
    challenge.extend_from_slice(&buf);
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let timestamp_bytes = timestamp.to_be_bytes();
    challenge.push(timestamp_bytes[0]);
    challenge.push(timestamp_bytes[1]);
    challenge.push(timestamp_bytes[2]);
    challenge.push(timestamp_bytes[3]);
    let signature = challenge_signature(&challenge);
    challenge.extend_from_slice(signature.as_ref());
    Some(challenge)
}

fn verify_challenge(challenge: &[u8], challenge_metadata: &ChallengeMetadata) -> bool {
    if challenge.len() < 70 {
        debug!("challenge too short");
        return false;
    }
    let uuid = &challenge[..16];
    let mut uuid_str = String::new();
    uuid[..4]
        .iter()
        .for_each(|it| write!(uuid_str, "{:02x}", it).unwrap());
    uuid_str.push('-');
    uuid[4..6]
        .iter()
        .for_each(|it| write!(uuid_str, "{:02x}", it).unwrap());
    uuid_str.push('-');
    uuid[6..8]
        .iter()
        .for_each(|it| write!(uuid_str, "{:02x}", it).unwrap());
    uuid_str.push('-');
    uuid[8..10]
        .iter()
        .for_each(|it| write!(uuid_str, "{:02x}", it).unwrap());
    uuid_str.push('-');
    uuid[10..]
        .iter()
        .for_each(|it| write!(uuid_str, "{:02x}", it).unwrap());
    if uuid_str != challenge_metadata.uuid {
        debug!("challenge uuid mismatch");
        return false;
    }
    let len = u16::from_be_bytes([challenge[16], challenge[17]]) as usize;
    // 16 (uuid) + 2 (json len) + len (json) + 32 (random) + 4 (timestamp) + 32 (signature) = 86 + len
    if challenge.len() != len + 86 {
        debug!("challenge length mismatch");
        return false;
    }
    if len == 0 && challenge_metadata.metadata.is_some() {
        debug!("missing challenge metadata");
        return false;
    }
    if len > 0 && challenge_metadata.metadata.is_none() {
        debug!("unexpected challenge metadata");
        return false;
    }
    if len > 0 {
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&challenge[38..]) {
            let metadata = challenge_metadata.metadata.as_ref().unwrap();
            if &value != metadata {
                debug!("challenge metadata mismatch");
                return false;
            }
        } else {
            debug!("challenge metadata mismatch");
        }
    }
    let timestamp: [u8; 4] = challenge[50 + len..54 + len].try_into().unwrap();
    let timestamp = u32::from_be_bytes(timestamp);
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let elapsed = now - timestamp;
    if timestamp > now || elapsed > CHALLENGE_VALIDITY_DURATION {
        debug!("challenge expired {now} - {timestamp} = {elapsed} > {CHALLENGE_VALIDITY_DURATION}");
        false
    } else {
        let signature = challenge_signature(&challenge[..len + 54]);
        signature.as_ref() == &challenge[len + 54..]
    }
}

//noinspection DuplicatedCode
pub(crate) async fn handle_auth(
    request: Request<Incoming>,
    server_name: &Arc<String>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = &request.uri().path()[9..];
    let method = request.method();
    let snapshot = snapshot().await;
    let session_state = SessionState::from_headers(request.headers(), &snapshot).await;
    let (user, session) = match session_state {
        SessionState::Valid { user, session } => (Some(user), Some(session)),
        SessionState::Expired { user } => (Some(user), None),
        _ => (None, None),
    };
    if path == "/credential_request_options" {
        if method != Method::POST {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, POST);
            debug!("405 https://{server_name}/api/auth/credential_request_options");
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        if let Some(challenge) = request
            .collect()
            .await
            .map(|it| it.to_bytes())
            .ok()
            .and_then(|body| serde_json::from_slice::<ChallengeMetadata>(body.as_ref()).ok())
            .and_then(|metadata| new_challenge(&metadata))
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
            debug!("200 https://{server_name}/api/auth/credential_request_options");
            return Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, JSON)
                .body(Either::Left(Full::from(
                    serde_json::to_vec(&credential_create).unwrap(),
                )))
                .unwrap();
        }
    } else if path == "/credentials" {
        if let Some(user) = user {
            if method != Method::HEAD {
                let mut response = Response::builder();
                let headers = response.headers_mut().unwrap();
                headers.insert(ALLOW, HEAD);
                debug!("405 https://{server_name}/api/auth/credentials");
                return response
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Either::Right(Empty::new()))
                    .unwrap();
            }
            return if let Some(first) = snapshot.list::<PassKey>(&format!("pk/{}/", user.id)).next()
            {
                debug!("{}", first.0);
                debug!("204 https://{server_name}/api/auth/credentials");
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Either::Right(Empty::new()))
                    .unwrap()
            } else {
                debug!("404 https://{server_name}/api/auth/credentials");
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Either::Right(Empty::new()))
                    .unwrap()
            };
        }
        debug!("403 https://{server_name}/api/auth/credentials");
    } else if path == "/credential_creation_options" {
        if session.is_none() {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        if method != Method::POST {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, POST);
            debug!("405 https://{server_name}/api/auth/credential_creation_options");
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        let user = user.unwrap();
        if let Some(challenge) = request
            .collect()
            .await
            .map(|it| it.to_bytes())
            .ok()
            .and_then(|body| serde_json::from_slice::<ChallengeMetadata>(body.as_ref()).ok())
            .and_then(|metadata| new_challenge(&metadata))
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
            debug!("200 https://{server_name}/api/auth/credential_creation_options");
            return Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, JSON)
                .body(Either::Left(Full::from(
                    serde_json::to_vec(&credential_creation).unwrap(),
                )))
                .unwrap();
        }
        debug!("403 https://{server_name}/api/auth/credential_creation_options");
    } else if path == "/record_credential" {
        if session.is_none() {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        if request.method() != Method::POST {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, POST);
            debug!("405 https://{server_name}/api/auth/record_credential");
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        let user = user.unwrap();
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
            let mut m = None;
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
                    Some("m") => {
                        if let Ok(it) = field.text().await {
                            if let Ok(it) = serde_json::from_str::<ChallengeMetadata>(&it) {
                                m = Some(it)
                            }
                        }
                    }
                    Some("c") => {
                        if let Ok(it) = field.bytes().await {
                            if let Ok(client_data) =
                                serde_json::from_slice::<ClientData>(it.as_ref())
                            {
                                if let Ok(challenge) =
                                    URL_SAFE_NO_PAD.decode_to_vec(client_data.challenge)
                                {
                                    if let Some(ref metadata) = m {
                                        challenge_verified = verify_challenge(&challenge, metadata)
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            if i.is_some() && challenge_verified {
                if let Some(passkey) = PassKey::new(i.unwrap(), a, k) {
                    if Snapshot::set(&format!("pk/{}/{}", user.id, passkey.id), &passkey)
                        .await
                        .is_some()
                    {
                        if let Some(session) =
                            User::create_session(user.id, &snapshot, Some(passkey.id)).await
                        {
                            debug!("200 https://{server_name}/api/auth/record_credential");
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
        }
        debug!("403 https://{server_name}/api/auth/record_credential");
    } else if path == "/validate_credential" {
        if request.method() != Method::POST {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, POST);
            debug!("405 https://{server_name}/api/auth/validate_credential");
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
            let mut m = None;
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
                    Some("m") => {
                        if let Ok(it) = field.text().await {
                            if let Ok(it) = serde_json::from_str::<ChallengeMetadata>(&it) {
                                m = Some(it)
                            }
                        }
                    }
                    Some("c") => {
                        if let Ok(it) = field.bytes().await {
                            if let Ok(client_data) =
                                serde_json::from_slice::<ClientData>(it.as_ref())
                            {
                                if let Ok(challenge) =
                                    URL_SAFE_NO_PAD.decode_to_vec(client_data.challenge)
                                {
                                    if let Some(ref metadata) = m {
                                        if verify_challenge(&challenge, metadata) {
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
                && !s.is_empty()
                && !d.is_empty()
                && digest(&SHA256, server_name.as_bytes()).as_ref() == &d[..32]
            {
                let passkey_id = i.unwrap();
                let user_id = u.unwrap();
                if snapshot
                    .get::<PassKey>(&format!("pk/{user_id}/{passkey_id}"))
                    .filter(|passkey| {
                        passkey.verify(s.as_slice(), d.as_slice(), hash.unwrap().as_slice())
                    })
                    .is_some()
                {
                    if let Some(session) =
                        User::create_session(user_id, &snapshot, Some(passkey_id)).await
                    {
                        debug!("200 https://{server_name}/api/auth/validate_credential");
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
        debug!("403 https://{server_name}/api/auth/validate_credential");
    } else if path == "/forget_user" {
        if request.method() != Method::GET {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, GET);
            debug!("405 https://{server_name}/api/auth/forget_user");
            return response
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Either::Right(Empty::new()))
                .unwrap();
        }
        if user.is_some() {
            if let Some(session) = session {
                Snapshot::delete([format!("sid/{}", session.id)].iter()).await;
            }
            debug!("200 https://{server_name}/api/auth/forget_user");
            let mut response = Response::builder().status(StatusCode::OK);
            let headers = response.headers_mut().unwrap();
            headers.append(SET_COOKIE, DELETE_ST_COOKIES);
            headers.append(SET_COOKIE, DELETE_SID_COOKIES);
            return response.body(Either::Right(Empty::new())).unwrap();
        }
        debug!("403 https://{server_name}/api/auth/forget_user");
    } else if path == "/disconnect_user" {
        if request.method() != Method::GET {
            let mut response = Response::builder();
            let headers = response.headers_mut().unwrap();
            headers.insert(ALLOW, GET);
            debug!("405 /api/auth/disconnect_user");
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
            debug!("302 https://{server_name}/api/auth/disconnect_user");
            let mut response = Response::builder().status(StatusCode::FOUND);
            let headers = response.headers_mut().unwrap();
            headers.insert(LOCATION, HeaderValue::from_static("/"));
            headers.append(SET_COOKIE, SID_EXPIRED);
            return response.body(Either::Right(Empty::new())).unwrap();
        }
        debug!("403 https://{server_name}/api/auth/disconnect_user");
    }
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Either::Right(Empty::new()))
        .unwrap()
}

#[cfg(test)]
mod tests_rsa {
    use crate::auth::PassKey;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::rand_core::{OsRng, RngCore};
    use rsa::sha2::Sha256;
    use rsa::signature::{SignatureEncoding, Signer};

    #[test]
    fn verify_rsa256() {
        let key_count = 3_usize;
        let payload_count = 3_usize;
        let mut rng = OsRng;
        for i in 0..key_count {
            let pkcs8 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let public_key = pkcs8.to_public_key();
            let spki = public_key.to_public_key_der().unwrap().to_vec();
            let signing_key = SigningKey::<Sha256>::new(pkcs8);
            for j in 0..payload_count {
                let len = 10
                    + rng
                        .next_u32()
                        .to_be_bytes()
                        .into_iter()
                        .map(|it| it as u16)
                        .sum::<u16>() as usize;
                let index = (rng.next_u32() % (len as u32 - 5)) as usize;
                let mut payload = vec![0u8; len];
                rng.fill_bytes(&mut payload);
                let signature = signing_key.sign(&payload).to_vec();
                let passkey =
                    PassKey::new(format!("{i}_{j}_{len}__rsa256"), -257, spki.clone()).unwrap();
                assert!(passkey.verify(&signature, &payload[..index], &payload[index..]));
            }
        }
    }
}

#[cfg(test)]
mod tests_ed25519 {
    use crate::auth::PassKey;
    use ed25519_dalek::ed25519::signature::rand_core::{OsRng, RngCore};
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn verify_ed25519() {
        let key_count = 3_usize;
        let payload_count = 3_usize;
        let mut rng = OsRng;
        for i in 0..key_count {
            let signing_key = SigningKey::generate(&mut rng);
            let public_key = signing_key.verifying_key();
            let spki = public_key.to_public_key_der().unwrap().to_vec();
            for j in 0..payload_count {
                let len = 10
                    + rng
                        .next_u32()
                        .to_be_bytes()
                        .into_iter()
                        .map(|it| it as u16)
                        .sum::<u16>() as usize;
                let index = (rng.next_u32() % (len as u32 - 5)) as usize;
                let mut payload = vec![0u8; len];
                rng.fill_bytes(&mut payload);
                let signature = signing_key.sign(&payload).to_vec();
                let passkey =
                    PassKey::new(format!("{i}_{j}_{len}__ed25519"), -8, spki.clone()).unwrap();
                assert!(passkey.verify(&signature, &payload[..index], &payload[index..]));
            }
        }
    }
}

#[cfg(test)]
mod tests_es256 {
    use crate::auth::PassKey;
    use p256::PublicKey;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::elliptic_curve::rand_core::{OsRng, RngCore};

    #[test]
    fn verify_es256() {
        let key_count = 3_usize;
        let payload_count = 3_usize;
        let mut rng = OsRng;
        for i in 0..key_count {
            let signing_key = SigningKey::random(&mut rng);
            let verifying_key = signing_key.verifying_key();
            let public_key =
                PublicKey::from_sec1_bytes(verifying_key.to_sec1_bytes().as_ref()).unwrap();
            let spki = p256::pkcs8::EncodePublicKey::to_public_key_der(&public_key)
                .unwrap()
                .to_vec();
            for j in 0..payload_count {
                let len = 10
                    + rng
                        .next_u32()
                        .to_be_bytes()
                        .into_iter()
                        .map(|it| it as u16)
                        .sum::<u16>() as usize;
                let index = (rng.next_u32() % (len as u32 - 5)) as usize;
                let mut payload = vec![0u8; len];
                rng.fill_bytes(&mut payload);
                let signature: Signature = signing_key.sign(&payload);
                let signature = signature.to_der().as_bytes().to_vec();
                let len = signature.len();
                let passkey =
                    PassKey::new(format!("{i}_{j}_{len}__ed25519"), -7, spki.clone()).unwrap();
                assert!(passkey.verify(&signature, &payload[..index], &payload[index..]));
            }
        }
    }
}
