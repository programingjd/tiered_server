use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use pinboard::NonEmptyPinboard;
use std::sync::Arc;
use tiered_server::api::Extension;
use tiered_server::server::serve;
use tiered_server::store::Snapshot;
use zip_static_handler::handler::Handler;

struct ApiExtension;

impl Extension for ApiExtension {
    async fn handle_api_extension(
        &self,
        _request: Request<Incoming>,
        _store_cache: &Arc<NonEmptyPinboard<Snapshot>>,
        _handler: Arc<Handler>,
        _server_name: Arc<String>,
    ) -> Option<Response<Either<Full<Bytes>, Empty<Bytes>>>> {
        None
    }
}

#[tokio::main]
async fn main() {
    serve(Box::leak(Box::new(ApiExtension))).await;
}
