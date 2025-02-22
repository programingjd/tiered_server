use crate::otp::handle_otp;
use crate::verify::handle_verify;
use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};

pub(crate) async fn handle_api(
    request: Request<Incoming>,
) -> Response<Either<Full<Bytes>, Empty<Bytes>>> {
    let path = &request.uri().path()[4..];
    if path.starts_with("/otp/") {
        return handle_otp(request).await;
    } else if path.starts_with("/verify/") {
        return handle_verify(request).await;
    }
    Response::new(Either::Right(Empty::new()))
}
