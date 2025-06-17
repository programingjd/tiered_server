use hyper::header::{HeaderName, HeaderValue};
use std::sync::LazyLock;
use zip_static_handler::handler::{HeaderSelector, HeadersAndCompression};
use zip_static_handler::http::headers::{
    ALLOW, CACHE_CONTROL, COEP, CONTENT_LENGTH, CONTENT_TYPE, COOP, CORP, CORS, CSP, HSTS, Line,
    SERVICE_WORKER_ALLOWED, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS, X_XSS_PROTECTION,
};

pub const JSON: HeaderValue = HeaderValue::from_static("application/json");
pub const GET: HeaderValue = HeaderValue::from_static("GET");
pub const HEAD: HeaderValue = HeaderValue::from_static("HEAD");
pub const POST: HeaderValue = HeaderValue::from_static("POST");
pub const GET_POST_PUT: HeaderValue = HeaderValue::from_static("GET, POST, PUT");

pub(crate) const X_HUB_SIGNATURE_256_HASH: HeaderName =
    HeaderName::from_static("x-hub-signature-256");
pub const X_ROBOTS_TAG: &[u8] = b"x-robots-tag";
pub const NOINDEX: &[u8] = b"noindex";
pub const CLOUDFLARE_CDN_CACHE_CONTROL: &[u8] = b"cloudflare-cdn-cache-control";
pub const CACHE_CONTROL_NOCACHE: &[u8] = b"no-cache";
pub const CACHE_CONTROL_REVALIDATE: &[u8] = b"public,max-age=0,stale-if-error=3600";
pub const CACHE_CONTROL_DEFAULT: &[u8] =
    b"public,max-age=72000,s-maxage=86400,stale-while-revalidate=28800,stale-if-error=3600";
pub const CACHE_CONTROL_IMMUTABLE: &[u8] =
    b"public,max-age=86400,s-maxage=86400,immutable,stale-while-revalidate=864000,stale-if-error=3600";

static DEFAULT_HEADERS: LazyLock<Vec<Line>> = LazyLock::new(|| {
    vec![
        (ALLOW, b"GET, HEAD".as_slice()).into(),
        (X_CONTENT_TYPE_OPTIONS, b"nosniff".as_slice()).into(),
        (X_FRAME_OPTIONS, b"DENY".as_slice()).into(),
        (X_XSS_PROTECTION, b"1; mode=block".as_slice()).into(),
        (
            CLOUDFLARE_CDN_CACHE_CONTROL,
            b"public,max-age=31536000,s-maxage=31536000,immutable".as_slice(),
        )
            .into(),
        (CORP, b"same-site".as_slice()).into(),
        (COEP, b"crendentialless".as_slice()).into(),
        (COOP, b"same-origin".as_slice()).into(),
        (
            CSP,
            b"\
                    default-src 'self';\
                    connect-src 'self' https: data: blob:;\
                    script-src 'wasm-unsafe-eval';\
                    script-src-elem 'self' 'unsafe-inline';\
                    script-src-attr 'none';\
                    worker-src 'self' blob:;\
                    style-src 'self' 'unsafe-inline';\
                    img-src 'self' data: blob:;\
                    font-src 'self' data:;\
                    frame-src 'none';\
                    object-src 'none';\
                    base-uri 'none';\
                    frame-ancestors 'none';\
                    form-action 'none'\
                "
            .as_slice(),
        )
            .into(),
        (
            HSTS,
            b"max-age=63072000; includeSubDomains; preload".as_slice(),
        )
            .into(),
    ]
});

pub static ERROR_HEADERS: LazyLock<Vec<Line>> = LazyLock::new(|| {
    let headers = vec![
        (ALLOW, b"GET, HEAD".as_slice()).into(),
        (CONTENT_LENGTH, b"0".as_slice()).into(),
        // (HSTS, b"max-age=63072000; includeSubDomains; preload".as_slice()),
    ];
    headers
});

pub(crate) struct HSelector;

impl HeaderSelector for HSelector {
    fn headers_for_extension(
        &self,
        filename: &str,
        extension: &str,
    ) -> Option<HeadersAndCompression> {
        headers_for_type(filename, extension, None)
    }

    fn error_headers(&self) -> &'static [Line] {
        default_error_headers()
    }
}

pub(crate) fn headers_for_type(
    filename: &str,
    extension: &str,
    cors_origin: Option<&str>,
) -> Option<HeadersAndCompression> {
    match extension {
        "html" | "htm" => Some(headers_and_compression(
            Some(b"text/html"),
            Some(CACHE_CONTROL_REVALIDATE),
            true,
            true,
            cors_origin,
        )),
        "css" => Some(headers_and_compression(
            Some(b"text/css"),
            Some(CACHE_CONTROL_REVALIDATE),
            true,
            true,
            cors_origin,
        )),
        "js" | "mjs" | "map" => Some(
            if filename.starts_with("service-worker.") || filename.starts_with("sw.") {
                let mut headers_and_compression = headers_and_compression(
                    Some(b"application/javascript"),
                    Some(CACHE_CONTROL_REVALIDATE),
                    true,
                    true,
                    cors_origin,
                );
                headers_and_compression
                    .headers
                    .push(Line::with_array_ref_value(SERVICE_WORKER_ALLOWED, b"/"));
                headers_and_compression
            } else {
                headers_and_compression(
                    Some(b"application/javascript"),
                    Some(CACHE_CONTROL_REVALIDATE),
                    true,
                    true,
                    cors_origin,
                )
            },
        ),
        "json" => Some(
            if filename.starts_with("manifest.") || filename.ends_with(".manifest") {
                headers_and_compression(
                    Some(b"application/manifest+json"),
                    Some(CACHE_CONTROL_DEFAULT),
                    true,
                    true,
                    cors_origin,
                )
            } else if filename.ends_with(".ld") {
                headers_and_compression(
                    Some(b"application/ld+json"),
                    Some(CACHE_CONTROL_DEFAULT),
                    true,
                    true,
                    cors_origin,
                )
            } else if filename.ends_with(".schema") {
                headers_and_compression(
                    Some(b"application/schema+json"),
                    Some(CACHE_CONTROL_DEFAULT),
                    true,
                    true,
                    cors_origin,
                )
            } else {
                headers_and_compression(
                    Some(b"application/json"),
                    Some(CACHE_CONTROL_REVALIDATE),
                    true,
                    true,
                    cors_origin,
                )
            },
        ),
        "xml" => Some(
            if filename.starts_with("atom.") || filename.ends_with(".atom") {
                headers_and_compression(
                    Some(b"application/atom+xml"),
                    Some(CACHE_CONTROL_DEFAULT),
                    true,
                    true,
                    cors_origin,
                )
            } else if filename.ends_with(".dtd") {
                headers_and_compression(
                    Some(b"application/xnl-dtd"),
                    Some(CACHE_CONTROL_DEFAULT),
                    true,
                    true,
                    cors_origin,
                )
            } else {
                headers_and_compression(
                    Some(b"application/xml"),
                    Some(CACHE_CONTROL_REVALIDATE),
                    true,
                    true,
                    cors_origin,
                )
            },
        ),
        "ldjson" => Some(headers_and_compression(
            Some(b"application/ld+json"),
            Some(CACHE_CONTROL_DEFAULT),
            true,
            true,
            cors_origin,
        )),
        "txt" => Some(headers_and_compression(
            Some(b"text/plain"),
            Some(CACHE_CONTROL_REVALIDATE),
            true,
            true,
            cors_origin,
        )),
        "csv" => Some(headers_and_compression(
            Some(b"text/csv"),
            Some(CACHE_CONTROL_REVALIDATE),
            true,
            true,
            cors_origin,
        )),
        "md" => Some(headers_and_compression(
            Some(b"text/markdown"),
            Some(CACHE_CONTROL_REVALIDATE),
            true,
            true,
            cors_origin,
        )),
        "wasm" => Some(headers_and_compression(
            Some(b"application/wasm"),
            Some(CACHE_CONTROL_REVALIDATE),
            true,
            true,
            cors_origin,
        )),
        "woff2" => Some(headers_and_compression(
            Some(b"font/woff2"),
            Some(CACHE_CONTROL_REVALIDATE),
            false,
            true,
            cors_origin,
        )),
        "ico" => Some(headers_and_compression(
            Some(b"image/x-icon"),
            Some(CACHE_CONTROL_IMMUTABLE),
            true,
            true,
            cors_origin,
        )),
        "webp" => Some(headers_and_compression(
            Some(b"image/webp"),
            Some(CACHE_CONTROL_IMMUTABLE),
            false,
            true,
            cors_origin,
        )),
        "avif" => Some(headers_and_compression(
            Some(b"image/avif"),
            Some(CACHE_CONTROL_IMMUTABLE),
            false,
            true,
            cors_origin,
        )),
        "gif" => Some(headers_and_compression(
            Some(b"image/gif"),
            Some(CACHE_CONTROL_IMMUTABLE),
            false,
            true,
            cors_origin,
        )),
        "heif" => Some(headers_and_compression(
            Some(b"image/heif"),
            Some(CACHE_CONTROL_IMMUTABLE),
            false,
            true,
            cors_origin,
        )),
        "heic" => Some(headers_and_compression(
            Some(b"image/heic"),
            Some(CACHE_CONTROL_IMMUTABLE),
            false,
            true,
            cors_origin,
        )),
        "png" => Some(headers_and_compression(
            Some(b"image/png"),
            Some(CACHE_CONTROL_IMMUTABLE),
            false,
            true,
            cors_origin,
        )),
        "jpg" => Some(headers_and_compression(
            Some(b"image/jpeg"),
            Some(CACHE_CONTROL_IMMUTABLE),
            false,
            true,
            cors_origin,
        )),
        "aac" => Some(headers_and_compression(
            Some(b"audio/aac"),
            Some(CACHE_CONTROL_REVALIDATE),
            false,
            false,
            cors_origin,
        )),
        "mp3" => Some(headers_and_compression(
            Some(b"audio/mp3"),
            Some(CACHE_CONTROL_REVALIDATE),
            false,
            false,
            cors_origin,
        )),
        "flac" => Some(headers_and_compression(
            Some(b"audio/flac"),
            Some(CACHE_CONTROL_REVALIDATE),
            false,
            false,
            cors_origin,
        )),
        "webm" => Some(headers_and_compression(
            Some(b"audio/webm"),
            Some(CACHE_CONTROL_REVALIDATE),
            false,
            false,
            cors_origin,
        )),
        "mp4" => Some(headers_and_compression(
            Some(b"video/mp4"),
            Some(CACHE_CONTROL_REVALIDATE),
            false,
            false,
            cors_origin,
        )),
        "svg" => Some(headers_and_compression(
            Some(b"image/svg+xml"),
            Some(CACHE_CONTROL_IMMUTABLE),
            true,
            true,
            cors_origin,
        )),
        "pdf" => Some(headers_and_compression(
            Some(b"application/pdf"),
            Some(CACHE_CONTROL_REVALIDATE),
            true,
            true,
            cors_origin,
        )),
        "zip" => Some(headers_and_compression(
            Some(b"application/zip"),
            Some(CACHE_CONTROL_REVALIDATE),
            false,
            true,
            cors_origin,
        )),
        "gpx" => Some(headers_and_compression(
            Some(b"application/gpx+xml"),
            Some(CACHE_CONTROL_DEFAULT),
            true,
            true,
            cors_origin,
        )),
        "kml" => Some(headers_and_compression(
            Some(b"application/vnd.google-earth.kml+xml"),
            Some(CACHE_CONTROL_DEFAULT),
            true,
            true,
            cors_origin,
        )),
        "geojson" => Some(headers_and_compression(
            Some(b"application/geo+json"),
            Some(CACHE_CONTROL_DEFAULT),
            true,
            true,
            cors_origin,
        )),
        "glb" => Some(headers_and_compression(
            Some(b"model/gltf-binary"),
            Some(CACHE_CONTROL_DEFAULT),
            true,
            true,
            cors_origin,
        )),
        "bin" => Some(headers_and_compression(
            Some(b"application/octet-stream"),
            Some(CACHE_CONTROL_REVALIDATE),
            true,
            true,
            cors_origin,
        )),
        "jinja" => Some(headers_and_compression(
            Some(b"text/html"),
            None,
            false,
            false,
            None,
        )),
        "307" => Some(headers_and_compression(
            None,
            Some(CACHE_CONTROL_REVALIDATE),
            false,
            true,
            None,
        )),
        "308" => Some(headers_and_compression(None, None, false, true, None)),
        _ => None,
    }
}

fn default_error_headers() -> &'static [Line] {
    ERROR_HEADERS.as_slice()
}

fn default_headers() -> impl Iterator<Item = &'static Line> {
    DEFAULT_HEADERS.iter()
}

fn headers_and_compression(
    content_type: Option<&'static [u8]>,
    cache_control: Option<&'static [u8]>,
    compressible: bool,
    allow_index: bool,
    cors_origin: Option<&str>,
) -> HeadersAndCompression {
    let default_headers = default_headers();
    let mut new_headers = vec![];
    if let Some(content_type) = content_type {
        new_headers.push(Line::with_slice_value(CONTENT_TYPE, content_type));
    }
    if let Some(cache_control) = cache_control {
        new_headers.push(Line::with_slice_value(CACHE_CONTROL, cache_control));
    }
    if !allow_index {
        new_headers.push(Line::with_slice_value(X_ROBOTS_TAG, NOINDEX));
    }
    if let Some(origin) = cors_origin {
        new_headers.push(Line::with_owned_value(CORS, origin.as_bytes().to_vec()))
    }
    HeadersAndCompression {
        headers: if new_headers.is_empty() {
            default_headers.cloned().collect()
        } else {
            default_headers.cloned().chain(new_headers).collect()
        },
        compressible,
        redirection: content_type.is_none(),
    }
}
