//! HTTP client building

use anyhow::Result;
pub use reqwest::Client;
use std::time::Duration;

/// Build HTTP client with basic configuration
pub fn build_client(
    timeout: u64,
    max_redirects: usize,
    follow_redirects: bool,
    user_agent: String,
    headers: Option<Vec<(String, String)>>,
) -> Result<Client> {
    build_client_with_config(
        timeout,
        max_redirects,
        follow_redirects,
        user_agent,
        headers,
        None,
        true,
    )
}

/// Build HTTP client with full scanner configuration
pub fn build_client_with_config(
    timeout: u64,
    max_redirects: usize,
    follow_redirects: bool,
    user_agent: String,
    headers: Option<Vec<(String, String)>>,
    proxy: Option<String>,
    tls_verify: bool,
) -> Result<Client> {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(if follow_redirects {
            reqwest::redirect::Policy::limited(max_redirects)
        } else {
            reqwest::redirect::Policy::none()
        })
        .user_agent(user_agent)
        .gzip(true)
        .brotli(true)
        .danger_accept_invalid_certs(!tls_verify);

    if let Some(proxy_url) = proxy {
        let proxy = reqwest::Proxy::all(&proxy_url)?;
        builder = builder.proxy(proxy);
    }

    if let Some(h) = headers {
        let mut header_map = reqwest::header::HeaderMap::new();
        for (k, v) in h {
            let header_name = reqwest::header::HeaderName::from_bytes(k.as_bytes())?;
            let header_value = reqwest::header::HeaderValue::from_str(&v)?;
            header_map.insert(header_name, header_value);
        }
        builder = builder.default_headers(header_map);
    }

    Ok(builder.build()?)
}
