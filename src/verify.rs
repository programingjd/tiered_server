use crate::headers::POST;
use crate::otp::{ValidationMethod, token_signature};
use crate::store::set_otp;
use base64_simd::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::ALLOW;
use hyper::{Method, Request, Response, StatusCode};
use ring::digest::{Context, SHA512};
use ring::rand::{SecureRandom, SystemRandom};

pub(crate) async fn handle_verify(
    request: Request<Incoming>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    if request.method() != Method::POST {
        let mut response = Response::builder();
        let headers = response.headers_mut().unwrap();
        headers.insert(ALLOW, POST);
        return response
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Either::Right(Empty::new()))
            .unwrap();
    }
    if let Ok(body) = request.collect().await.map(|it| it.to_bytes()) {
        if let Ok(validation_method) = serde_json::from_slice::<ValidationMethod>(body.as_ref()) {
            let mut digest = Context::new(&SHA512);
            let rand = SystemRandom::new();
            let mut arr = [0u8; 16];
            rand.fill(&mut arr).unwrap();
            digest.update(&arr);
            digest.update(body.as_ref());
            rand.fill(&mut arr).unwrap();
            digest.update(&arr);
            let hash = digest.finish();
            let token = URL_SAFE_NO_PAD.encode_to_string(hash.as_ref());
            if set_otp(token.as_str(), &validation_method).await.is_some() {
                let signature = token_signature(token.as_str()).unwrap();
                let _link = format!("/otp/{token}.{signature}");
                todo!("send email")
            }
        }
    }
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Either::Right(Empty::new()))
        .unwrap()
}
