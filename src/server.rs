extern crate rustls as extern_rustls;

use crate::api::{Extension, handle_api};
use crate::env::ConfigurationKey::{BindAddress, DomainApex, DomainTitle};
use crate::env::secret_value;
use crate::firewalls::update_firewall_loop;
use crate::handler::static_handler;
use crate::prefix::{API_PATH_PREFIX, USER_PATH_PREFIX};
use crate::push_webhook::handle_webhook;
use crate::session::{LOGIN_PATH, SID_EXPIRED, SessionState};
use crate::store::snapshot;
use crate::user::ensure_admin_users_exist;
use extern_rustls::ServerConfig;
use extern_rustls::crypto::ring::sign::any_supported_type;
use extern_rustls::pki_types::PrivateKeyDer;
use extern_rustls::server::{Acceptor, ClientHello as RustClientHello, ResolvesServerCert};
use extern_rustls::sign::CertifiedKey;
use firewall::Accept;
use firewall::builder::Firewall;
use firewall::cloudflare::fetch_cloudflare_ip_ranges;
use firewall::github::fetch_github_webhook_ip_ranges;
use http_body_util::{Either, Empty};
use hyper::header::{HeaderValue, LOCATION, SET_COOKIE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Response, StatusCode};
use hyper_util::rt::TokioIo;
use pinboard::NonEmptyPinboard;
use rcgen::generate_simple_self_signed;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::sync::{Arc, LazyLock};
use tokio::net::TcpListener;
use tokio::spawn;
use tokio_rustls::LazyConfigAcceptor;
use tracing::info;
use zip_static_handler::http::headers::CONTENT_TYPE;

const HTML: &[u8] = b"text/html";

//noinspection SpellCheckingInspection
pub static DOMAIN_APEX: LazyLock<&'static str> =
    LazyLock::new(|| secret_value(DomainApex).expect("missing domain name"));

//noinspection SpellCheckingInspection
pub static DOMAIN_TITLE: LazyLock<&'static str> =
    LazyLock::new(|| secret_value(DomainTitle).expect("missing domain title"));

#[derive(Debug)]
struct LocalhostResolver {
    key: Arc<CertifiedKey>,
}

impl Default for LocalhostResolver {
    /// Create self-signed certificate for domain "localhost" and ip "127.0.0.1".
    fn default() -> Self {
        let cert = generate_simple_self_signed(vec![
            "localhost".to_string(),
            format!("{}", Ipv4Addr::LOCALHOST),
        ])
        .expect("failed to generate self-signed certificate for localhost");
        let key = Arc::new(CertifiedKey::new(
            vec![cert.cert.der().to_vec().into()],
            any_supported_type(&PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()))
                .expect("failed to generate signing key"),
        ));
        Self { key }
    }
}

impl ResolvesServerCert for LocalhostResolver {
    fn resolve(&self, _client_hello: RustClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.key.clone())
    }
}

pub async fn serve<Ext: Extension + Send + Sync>(extension: &'static Ext) {
    let cloudflare_ip_ranges = fetch_cloudflare_ip_ranges()
        .await
        .expect("failed to fetch cloudflare ip ranges");
    let github_ip_ranges = fetch_github_webhook_ip_ranges()
        .await
        .expect("failed to fetch github webhook ip ranges");
    let _domain_title = *DOMAIN_TITLE;
    let domain_apex = *DOMAIN_APEX;
    let domains = vec![
        domain_apex.to_string(),
        format!("www.{domain_apex}"),
        format!("{domain_apex}.localhost"),
        "localhost".to_string(),
        "www.localhost".to_string(),
    ];
    let firewall = Arc::new(NonEmptyPinboard::new(
        Firewall::default()
            .require_sni()
            .allow_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .allow_ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
            .allow_ip_ranges(cloudflare_ip_ranges.iter().cloned())
            .allow_server_names(domains.iter().cloned()),
    ));
    let webhook_firewall = Arc::new(NonEmptyPinboard::new(
        Firewall::default()
            .require_sni()
            .allow_ip_ranges(github_ip_ranges.iter().cloned())
            .allow_ip_ranges(cloudflare_ip_ranges.iter().cloned())
            .allow_server_names(domains.iter().cloned()),
    ));

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(LocalhostResolver::default()));

    update_firewall_loop(
        firewall.clone(),
        webhook_firewall.clone(),
        domains.clone(),
        domains.clone(),
        cloudflare_ip_ranges.clone(),
        github_ip_ranges.clone(),
    );

    let api_path_prefix = API_PATH_PREFIX.deref();
    let user_path_prefix = USER_PATH_PREFIX.deref();
    let login_path = *LOGIN_PATH.deref();
    let listener = TcpListener::bind((secret_value(BindAddress).unwrap_or("0.0.0.0"), 443u16))
        .await
        .expect("could not bind to 443");

    ensure_admin_users_exist(&snapshot(), &static_handler())
        .await
        .expect("failed to get or create admin users");

    loop {
        if let Ok((tcp_stream, remote_address)) = listener.accept().await {
            let firewall = firewall.clone();
            let webhook_firewall = webhook_firewall.clone();
            let config = config.clone();
            spawn(async move {
                let acceptor = LazyConfigAcceptor::new(Acceptor::default(), tcp_stream);
                if let Ok(start_handshake) = acceptor.await {
                    let client_hello = &start_handshake.client_hello();
                    let ip = remote_address.ip();
                    // webhook calls should all originate from GitHub servers
                    let is_webhook = if firewall.get_ref().accept(ip, Some(client_hello)) {
                        false
                    }
                    // all other requests should original from Cloudflare servers
                    else if webhook_firewall.get_ref().accept(ip, Some(client_hello)) {
                        true
                    } else {
                        return;
                    };
                    let server_name = Arc::new(client_hello.server_name().unwrap().to_string());
                    if let Ok(stream) = start_handshake.into_stream(Arc::new(config)).await {
                        let io = TokioIo::new(stream);
                        let _ = http1::Builder::new()
                            .serve_connection(
                                io,
                                service_fn(move |request| {
                                    let server_name = server_name.clone();
                                    async move {
                                        let path = request.uri().path();
                                        // webhook call from the GitHub repository that notifies
                                        // that the static content should be updated
                                        if is_webhook || path == "/github_push_webhook" {
                                            Ok::<_, Infallible>(
                                                handle_webhook(request).await,
                                            )
                                        }
                                        // api requests
                                        else {
                                            let handler = static_handler();
                                            if api_path_prefix.matches(path) {
                                            Ok::<_, Infallible>(
                                                handle_api(request, &server_name, extension).await,
                                            )
                                            } else {
                                                if user_path_prefix.matches(path) {
                                                    // user scoped html pages that require login
                                                    if let Some(HTML) =
                                                        handler.entry(path).and_then(|it| {
                                                            it.headers.iter().find_map(|it| {
                                                                if it.key == CONTENT_TYPE {
                                                                    Some(it.value.as_ref())
                                                                } else {
                                                                    None
                                                                }
                                                            })
                                                        })
                                                    {
                                                        let snapshot = snapshot();
                                                        match SessionState::from_headers(
                                                            request.headers(),
                                                            &snapshot,
                                                        )
                                                        .await
                                                        {
                                                            SessionState::Valid { .. } => {}
                                                            _ => {
                                                                // redirect to the login page
                                                                let response = match request.method() {
                                                                    &Method::HEAD | &Method::GET => {
                                                                        info!("302 https://{server_name}{path}");
                                                                        let mut response =
                                                                            Response::builder().status(
                                                                                StatusCode::FOUND,
                                                                            );
                                                                        let headers = response
                                                                            .headers_mut()
                                                                            .unwrap();
                                                                        headers.insert(
                                                                            LOCATION,
                                                                            HeaderValue::from_static(
                                                                                login_path,
                                                                            ),
                                                                        );
                                                                        headers.append(
                                                                            SET_COOKIE,
                                                                            SID_EXPIRED,
                                                                        );
                                                                        response
                                                                    }
                                                                    _ => {
                                                                        info!("403 https://{server_name}{path}");
                                                                        Response::builder().status(
                                                                            StatusCode::FORBIDDEN,
                                                                        )
                                                                    }
                                                                };
                                                                return Ok::<_, Infallible>(
                                                                    response
                                                                        .body(Either::Right(
                                                                            Empty::new(),
                                                                        ))
                                                                        .unwrap(),
                                                                );
                                                            }
                                                        }
                                                    }
                                                }
                                                // static content
                                                let path = path.to_string();
                                                let response = handler.handle_hyper_request(request);
                                                info!("{} https://{server_name}{path}", response.status().as_u16());
                                                Ok::<_, Infallible>(response)
                                            }
                                        }
                                    }
                                }),
                            )
                            .await;
                    }
                }
            });
        }
    }
}
