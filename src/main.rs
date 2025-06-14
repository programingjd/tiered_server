use http_body_util::{Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use std::sync::Arc;
use tiered_server::api::Extension;
use tiered_server::server::serve;

struct ApiExtension;

impl Extension for ApiExtension {
    async fn handle_api_extension(
        &self,
        _request: Request<Incoming>,
        _server_name: &Arc<String>,
    ) -> Option<Response<Either<Full<Bytes>, Empty<Bytes>>>> {
        None
    }
}

#[tokio::main]
async fn main() {
    #[cfg(debug_assertions)]
    tracing_subscriber::fmt()
        .compact()
        .with_ansi(true)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .without_time()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "tiered_server=debug,zip_static_handler=info,hyper=info",
        ))
        .init();
    #[cfg(not(debug_assertions))]
    tracing_subscriber::fmt()
        .compact()
        .with_ansi(true)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .without_time()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "tiered_server=warn,zip_static_handler=info,hyper=info",
        ))
        .init();
    serve(Box::leak(Box::new(ApiExtension))).await;
}
