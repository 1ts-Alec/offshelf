//! Serves the web app (apps/web) on the same LAN port as the API. The files
//! are public: nothing in them is secret, and the app only gets at the shelf
//! after pairing and unlocking in the browser.

use std::path::{Component, Path, PathBuf};

use axum::body::Body;
use axum::http::{header, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};

/// Where the built web app comes from.
#[derive(Debug, Clone)]
pub enum WebApp {
    /// A `dist` folder on disk (`--web-dir`).
    Dir(PathBuf),
    /// Compiled into the binary with the `web` feature.
    #[cfg(feature = "web")]
    Embedded,
}

#[cfg(feature = "web")]
static EMBEDDED: include_dir::Dir<'_> = include_dir::include_dir!("$CARGO_MANIFEST_DIR/../../apps/web/dist");

impl WebApp {
    /// The embedded app when built with it, else none.
    pub fn default_app() -> Option<WebApp> {
        #[cfg(feature = "web")]
        {
            Some(WebApp::Embedded)
        }
        #[cfg(not(feature = "web"))]
        {
            None
        }
    }

    async fn read(&self, rel: &str) -> Option<Vec<u8>> {
        match self {
            WebApp::Dir(root) => tokio::fs::read(root.join(rel)).await.ok(),
            #[cfg(feature = "web")]
            WebApp::Embedded => EMBEDDED.get_file(rel).map(|f| f.contents().to_vec()),
        }
    }
}

/// Lock the page down: only its own scripts, WebAssembly, and blob URLs for
/// decrypted previews. Nothing is loaded from anywhere but the Pi.
const CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; \
    img-src 'self' blob: data:; media-src 'self' blob:; frame-src 'self' blob:; worker-src 'self' blob:; \
    connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, e)| e) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ttf") => "font/ttf",
        Some("woff2") => "font/woff2",
        Some("json") | Some("webmanifest") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Maps a request path to a file inside the app, refusing anything that
/// could climb out of it.
fn relative(path: &str) -> Option<String> {
    let trimmed = path.trim_start_matches('/');
    let rel = if trimmed.is_empty() { "index.html" } else { trimmed };
    let ok = Path::new(rel).components().all(|c| matches!(c, Component::Normal(_)));
    ok.then(|| rel.to_string())
}

pub async fn serve(app: &WebApp, req: Request<Body>) -> Response {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let Some(rel) = relative(req.uri().path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(bytes) = app.read(&rel).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Vite puts a content hash in every file name under assets/.
    let cache = if rel.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    let mut res = (StatusCode::OK, bytes).into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type(&rel)));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_stay_inside() {
        assert_eq!(relative("/").as_deref(), Some("index.html"));
        assert_eq!(relative("/assets/app.js").as_deref(), Some("assets/app.js"));
        assert_eq!(relative("/../secret"), None);
        assert_eq!(relative("/assets/../../x"), None);
        assert_eq!(relative("/./x"), None);
    }
}
