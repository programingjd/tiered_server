use crate::auth::passkey::challenge::{ChallengeMetadata, ClientData};
use crate::auth::passkey::{PassKey, challenge};
use crate::browser::browser_info;
use crate::prefix::API_PATH_PREFIX;
use crate::store::Snapshot;
use crate::user::User;
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONTENT_TYPE, SET_COOKIE};
use hyper::{Request, Response, StatusCode};
use multer::{Constraints, Multipart, SizeLimit, parse_boundary};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::info;

#[allow(clippy::unnecessary_unwrap)]
pub(crate) async fn post(
    request: Request<Incoming>,
    snapshot: &Arc<Snapshot>,
    user: User,
) -> Option<Response<Either<Full<Bytes>, Empty<Bytes>>>> {
    if let Some(boundary) = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|it| it.to_str().ok())
        .and_then(|it| parse_boundary(it).ok())
    {
        let browser_info = browser_info(request.headers());
        let mut multipart = Multipart::with_constraints(
            request.into_body().into_data_stream(),
            boundary,
            Constraints::new().size_limit(SizeLimit::new().whole_stream(4_096)),
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
                        if let Ok(client_data) = serde_json::from_slice::<ClientData>(it.as_ref()) {
                            if let Ok(challenge) =
                                URL_SAFE_NO_PAD.decode_to_vec(client_data.challenge)
                            {
                                if let Some(ref metadata) = m {
                                    challenge_verified = challenge::verify(&challenge, metadata)
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if i.is_some() && challenge_verified {
            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;
            if let Some(passkey) = PassKey::new(i.unwrap(), timestamp, browser_info, a, k) {
                if Snapshot::set_and_wait_for_update(
                    &format!("pk/{}/{}", user.id, passkey.id),
                    &passkey,
                )
                .await
                .is_some()
                {
                    if let Some(session) =
                        User::create_session(&user, snapshot, Some(passkey.id), false).await
                    {
                        info!(
                            "200 {}/auth/record_credential",
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
    }
    None
}
