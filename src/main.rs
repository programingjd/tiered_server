use tiered_server::server::serve;

#[tokio::main]
async fn main() {
    serve().await;
}
