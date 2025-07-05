use crate::auth::passkey::challenge::{ChallengeMetadata, ClientData};
use crate::auth::passkey::{PassKey, challenge};
use crate::prefix::API_PATH_PREFIX;
use crate::session::Session;
use crate::store::Snapshot;
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONTENT_TYPE, SET_COOKIE};
use hyper::{Request, Response, StatusCode};
use multer::{Constraints, Multipart, SizeLimit, parse_boundary};
use ring::digest::{SHA256, digest};
use std::sync::Arc;
use tracing::info;

pub(crate) async fn post(
    request: Request<Incoming>,
    server_name: &Arc<String>,
    snapshot: &Arc<Snapshot>,
) -> Option<Response<Either<Full<Bytes>, Empty<Bytes>>>> {
    if let Some(boundary) = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|it| it.to_str().ok())
        .and_then(|it| parse_boundary(it).ok())
    {
        let mut multipart = Multipart::with_constraints(
            request.into_body().into_data_stream(),
            boundary,
            Constraints::new().size_limit(SizeLimit::new().whole_stream(4_096)),
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
                        if let Ok(client_data) = serde_json::from_slice::<ClientData>(it.as_ref()) {
                            if let Ok(challenge) =
                                URL_SAFE_NO_PAD.decode_to_vec(client_data.challenge)
                            {
                                if let Some(ref metadata) = m {
                                    if challenge::verify(&challenge, metadata) {
                                        hash = Some(digest(&SHA256, it.as_ref()).as_ref().to_vec());
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
                    Session::create(user_id, snapshot, Some(passkey_id), false).await
                {
                    info!(
                        "200 {}/auth/validate_credential",
                        API_PATH_PREFIX.without_trailing_slash
                    );
                    let mut response = Response::builder().status(StatusCode::OK);
                    let headers = response.headers_mut().unwrap();
                    session.cookies(false).into_iter().for_each(|cookie| {
                        headers.append(SET_COOKIE, cookie);
                    });
                    return Some(response.body(Either::Right(Empty::new())).unwrap());
                };
            }
        }
    }
    None
}
