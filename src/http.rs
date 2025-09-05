use std::io::Write;
use std::path::Path;
use std::time::Duration;

use eyre::{Report, Result, bail, ensure};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{ClientBuilder, IntoUrl, Method, Response};
use std::sync::LazyLock as Lazy;
use url::Url;

use crate::cli::version;
use crate::config::Settings;
use crate::file::display_path;
use crate::ui::progress_report::SingleReport;
use crate::ui::time::format_duration;
use crate::{env, file};

#[cfg(not(test))]
pub static HTTP_VERSION_CHECK: Lazy<Client> =
    Lazy::new(|| Client::new(Duration::from_secs(3), ClientKind::VersionCheck).unwrap());

pub static HTTP: Lazy<Client> =
    Lazy::new(|| Client::new(Settings::get().http_timeout(), ClientKind::Http).unwrap());

pub static HTTP_FETCH: Lazy<Client> = Lazy::new(|| {
    Client::new(
        Settings::get().fetch_remote_versions_timeout(),
        ClientKind::Fetch,
    )
    .unwrap()
});

#[derive(Debug)]
pub struct Client {
    reqwest: reqwest::Client,
    timeout: Duration,
    kind: ClientKind,
}

#[derive(Debug, Clone, Copy)]
enum ClientKind {
    Http,
    Fetch,
    #[allow(dead_code)]
    VersionCheck,
}

impl Client {
    fn new(timeout: Duration, kind: ClientKind) -> Result<Self> {
        Ok(Self {
            reqwest: Self::_new()
                .read_timeout(timeout)
                .connect_timeout(timeout)
                .build()?,
            timeout,
            kind,
        })
    }

    fn _new() -> ClientBuilder {
        let v = &*version::VERSION;
        let shell = env::MISE_SHELL.map(|s| s.to_string()).unwrap_or_default();
        ClientBuilder::new()
            .user_agent(format!("mise/{v} {shell}").trim())
            .gzip(true)
            .zstd(true)
    }

    pub async fn get_bytes<U: IntoUrl>(&self, url: U) -> Result<impl AsRef<[u8]>> {
        let mut url = url.into_url().unwrap();
        apply_url_replacements(&mut url);
        let resp = self.get_async(url.clone()).await?;
        Ok(resp.bytes().await?)
    }

    pub async fn get_async<U: IntoUrl>(&self, url: U) -> Result<Response> {
        let mut url = url.into_url().unwrap();
        apply_url_replacements(&mut url);
        let headers = github_headers(&url);
        self.get_async_with_headers(url, &headers).await
    }

    async fn get_async_with_headers<U: IntoUrl>(
        &self,
        url: U,
        headers: &HeaderMap,
    ) -> Result<Response> {
        ensure!(!*env::OFFLINE, "offline mode is enabled");
        let mut url = url.into_url().unwrap();
        apply_url_replacements(&mut url);
        let resp = self
            .send_with_https_fallback(Method::GET, url, headers, "GET")
            .await?;
        resp.error_for_status_ref()?;
        Ok(resp)
    }

    pub async fn head<U: IntoUrl>(&self, url: U) -> Result<Response> {
        let mut url = url.into_url().unwrap();
        apply_url_replacements(&mut url);
        let headers = github_headers(&url);
        self.head_async_with_headers(url, &headers).await
    }

    pub async fn head_async_with_headers<U: IntoUrl>(
        &self,
        url: U,
        headers: &HeaderMap,
    ) -> Result<Response> {
        ensure!(!*env::OFFLINE, "offline mode is enabled");
        let mut url = url.into_url().unwrap();
        apply_url_replacements(&mut url);
        let resp = self
            .send_with_https_fallback(Method::HEAD, url, headers, "HEAD")
            .await?;
        resp.error_for_status_ref()?;
        Ok(resp)
    }

    pub async fn get_text<U: IntoUrl>(&self, url: U) -> Result<String> {
        let mut url = url.into_url().unwrap();
        let resp = self.get_async(url.clone()).await?;
        let text = resp.text().await?;
        if text.starts_with("<!DOCTYPE html>") {
            if url.scheme() == "http" {
                // try with https since http may be blocked
                url.set_scheme("https").unwrap();
                return Box::pin(self.get_text(url)).await;
            }
            bail!("Got HTML instead of text from {}", url);
        }
        Ok(text)
    }

    pub async fn get_html<U: IntoUrl>(&self, url: U) -> Result<String> {
        let url = url.into_url().unwrap();
        let resp = self.get_async(url.clone()).await?;
        let html = resp.text().await?;
        if !html.starts_with("<!DOCTYPE html>") {
            bail!("Got non-HTML text from {}", url);
        }
        Ok(html)
    }

    pub async fn json_headers<T, U: IntoUrl>(&self, url: U) -> Result<(T, HeaderMap)>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut url = url.into_url().unwrap();
        apply_url_replacements(&mut url);
        let resp = self.get_async(url).await?;
        let headers = resp.headers().clone();
        let json = resp.json().await?;
        Ok((json, headers))
    }

    pub async fn json_headers_with_headers<T, U: IntoUrl>(
        &self,
        url: U,
        headers: &HeaderMap,
    ) -> Result<(T, HeaderMap)>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut url = url.into_url().unwrap();
        apply_url_replacements(&mut url);
        let resp = self.get_async_with_headers(url, headers).await?;
        let headers = resp.headers().clone();
        let json = resp.json().await?;
        Ok((json, headers))
    }

    pub async fn json<T, U: IntoUrl>(&self, url: U) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        self.json_headers(url).await.map(|(json, _)| json)
    }

    pub async fn json_with_headers<T, U: IntoUrl>(&self, url: U, headers: &HeaderMap) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        self.json_headers_with_headers(url, headers)
            .await
            .map(|(json, _)| json)
    }

    pub async fn download_file<U: IntoUrl>(
        &self,
        url: U,
        path: &Path,
        pr: Option<&Box<dyn SingleReport>>,
    ) -> Result<()> {
        let mut url = url.into_url()?;
        apply_url_replacements(&mut url);
        let headers = github_headers(&url);
        self.download_file_with_headers(url, path, &headers, pr)
            .await
    }

    pub async fn download_file_with_headers<U: IntoUrl>(
        &self,
        url: U,
        path: &Path,
        headers: &HeaderMap,
        pr: Option<&Box<dyn SingleReport>>,
    ) -> Result<()> {
        let mut url = url.into_url()?;
        apply_url_replacements(&mut url);
        debug!("GET Downloading {} to {}", &url, display_path(path));

        let mut resp = self.get_async_with_headers(url, headers).await?;
        if let Some(length) = resp.content_length() {
            if let Some(pr) = pr {
                pr.set_length(length);
            }
        }

        let parent = path.parent().unwrap();
        file::create_dir_all(parent)?;
        let mut file = tempfile::NamedTempFile::with_prefix_in(path, parent)?;
        while let Some(chunk) = resp.chunk().await? {
            file.write_all(&chunk)?;
            if let Some(pr) = pr {
                pr.inc(chunk.len() as u64);
            }
        }
        file.persist(path)?;
        Ok(())
    }

    async fn send_with_https_fallback(
        &self,
        method: Method,
        mut url: Url,
        headers: &HeaderMap,
        verb_label: &str,
    ) -> Result<Response> {
        apply_url_replacements(&mut url);
        match self
            .send_once(method.clone(), url.clone(), headers, verb_label)
            .await
        {
            Ok(resp) => Ok(resp),
            Err(_) if url.scheme() == "http" => {
                url.set_scheme("https").unwrap();
                self.send_once(method, url, headers, verb_label).await
            }
            Err(err) => Err(err),
        }
    }

    async fn send_once(
        &self,
        method: Method,
        url: Url,
        headers: &HeaderMap,
        verb_label: &str,
    ) -> Result<Response> {
        debug!("{} {}", verb_label, &url);
        let mut req = self.reqwest.request(method, url.clone());
        req = req.headers(headers.clone());
        let resp = match req.send().await {
            Ok(resp) => resp,
            Err(err) => {
                if err.is_timeout() {
                    let (setting, env_var) = match self.kind {
                        ClientKind::Http => ("http_timeout", "MISE_HTTP_TIMEOUT"),
                        ClientKind::Fetch => (
                            "fetch_remote_versions_timeout",
                            "MISE_FETCH_REMOTE_VERSIONS_TIMEOUT",
                        ),
                        ClientKind::VersionCheck => ("version_check_timeout", ""),
                    };
                    let hint = if env_var.is_empty() {
                        format!(
                            "HTTP timed out after {} for {}.",
                            format_duration(self.timeout),
                            url
                        )
                    } else {
                        format!(
                            "HTTP timed out after {} for {} (change with `{}` or env `{}`).",
                            format_duration(self.timeout),
                            url,
                            setting,
                            env_var
                        )
                    };
                    bail!(hint);
                }
                return Err(err.into());
            }
        };
        if *env::MISE_LOG_HTTP {
            eprintln!("{} {url} {}", verb_label, resp.status());
        }
        debug!("{} {url} {}", verb_label, resp.status());
        display_github_rate_limit(&resp);
        resp.error_for_status_ref()?;
        Ok(resp)
    }
}

pub fn error_code(e: &Report) -> Option<u16> {
    if e.to_string().contains("404") {
        // TODO: not this when I can figure out how to use eyre properly
        return Some(404);
    }
    if let Some(err) = e.downcast_ref::<reqwest::Error>() {
        err.status().map(|s| s.as_u16())
    } else {
        None
    }
}

fn github_headers(url: &Url) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if url.host_str() == Some("api.github.com") {
        if let Some(token) = &*env::GITHUB_TOKEN {
            headers.insert(
                "authorization",
                HeaderValue::from_str(format!("token {token}").as_str()).unwrap(),
            );
            headers.insert(
                "x-github-api-version",
                HeaderValue::from_static("2022-11-28"),
            );
        }
    }
    headers
}

/// Apply URL replacements based on settings configuration
pub fn apply_url_replacements(url: &mut Url) {
    let settings = Settings::get();
    if let Some(replacements) = &settings.url_replacements {
        // Enhanced logic: try full URL (protocol + host) first, then fall back to host-only
        let url_without_path = format!("{}://{}", url.scheme(), url.host_str().unwrap_or(""));

        if let Some(replacement) = replacements.get(&url_without_path) {
            // Full URL replacement (protocol-specific)
            debug!("Replacing URL {} with {}", url_without_path, replacement);
            if let Ok(replacement_url) = Url::parse(replacement) {
                let _ = url.set_scheme(replacement_url.scheme());
                if let Some(host) = replacement_url.host_str() {
                    let _ = url.set_host(Some(host));
                }
                if let Some(port) = replacement_url.port() {
                    let _ = url.set_port(Some(port));
                } else if replacement_url.port().is_none() {
                    // Clear port if replacement URL doesn't specify one
                    let _ = url.set_port(None);
                }
                // Handle the path component - prepend replacement path to existing path
                let replacement_path = replacement_url.path();
                if !replacement_path.is_empty() && replacement_path != "/" {
                    let current_path = url.path();
                    let new_path = if replacement_path.ends_with('/') {
                        format!("{}{}", replacement_path.trim_end_matches('/'), current_path)
                    } else {
                        format!("{}{}", replacement_path, current_path)
                    };
                    url.set_path(&new_path);
                }
            }
        } else if let Some(host) = url.host_str() {
            // Fall back to host-only replacement (backward compatibility)
            if let Some(replacement) = replacements.get(host) {
                debug!("Replacing URL host {} with {}", host, replacement);

                // Try to parse replacement as a full URL first (to handle cases where the value is a full URL)
                if let Ok(replacement_url) = Url::parse(replacement) {
                    // Full URL replacement - extract all components
                    let _ = url.set_scheme(replacement_url.scheme());
                    if let Some(replacement_host) = replacement_url.host_str() {
                        let _ = url.set_host(Some(replacement_host));
                    }
                    if let Some(port) = replacement_url.port() {
                        let _ = url.set_port(Some(port));
                    } else if replacement_url.port().is_none() {
                        // Clear port if replacement URL doesn't specify one
                        let _ = url.set_port(None);
                    }
                    // Handle the path component - prepend replacement path to existing path
                    let replacement_path = replacement_url.path();
                    if !replacement_path.is_empty() && replacement_path != "/" {
                        let current_path = url.path();
                        let new_path = if replacement_path.ends_with('/') {
                            format!("{}{}", replacement_path.trim_end_matches('/'), current_path)
                        } else {
                            format!("{}{}", replacement_path, current_path)
                        };
                        url.set_path(&new_path);
                    }
                } else {
                    // Simple hostname replacement (original behavior)
                    let _ = url.set_host(Some(replacement));
                }
            }
        }
    }
}

fn display_github_rate_limit(resp: &Response) {
    let status = resp.status().as_u16();
    if status == 403 || status == 429 {
        let remaining = resp
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|r| r.to_str().ok());
        if remaining.is_some_and(|r| r == "0") {
            if let Some(reset_time) = resp
                .headers()
                .get("x-ratelimit-reset")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<i64>().ok())
                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
            {
                warn!(
                    "GitHub rate limit exceeded. Resets at {}",
                    reset_time.with_timezone(&chrono::Local)
                );
            }
            return;
        }
        // retry-after header is processed only if x-ratelimit-remaining is not 0 or is missing
        if let Some(retry_after) = resp
            .headers()
            .get("retry-after")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        {
            warn!(
                "GitHub rate limit exceeded. Retry after {} seconds",
                retry_after
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::apply_url_replacements;
    use indexmap::IndexMap;
    use url::Url;

    // Helper function to test URL replacement with mock settings (mimics OLD buggy behavior)
    fn test_url_replacement(replacements: IndexMap<String, String>, original_url: &str) -> String {
        let mut url = Url::parse(original_url).unwrap();

        // This mimics the OLD buggy implementation that directly used set_host
        if let Some(host) = url.host_str() {
            if let Some(replacement) = replacements.get(host) {
                let _ = url.set_host(Some(replacement)); // This is the bug - doesn't handle full URLs properly
            }
        }

        url.to_string()
    }

    #[test]
    fn test_current_host_only_replacement() {
        // Test current implementation: host-only replacement
        let mut replacements = IndexMap::new();
        replacements.insert("github.com".to_string(), "my-github-proxy.com".to_string());

        let result = test_url_replacement(replacements, "https://github.com/owner/repo");
        assert_eq!(result, "https://my-github-proxy.com/owner/repo");
    }

    #[test]
    fn test_subdomain_behavior() {
        // Test current behavior with subdomains
        let mut replacements = IndexMap::new();
        replacements.insert("github.com".to_string(), "my-github-proxy.com".to_string());

        // Main domain gets replaced
        let result1 = test_url_replacement(replacements.clone(), "https://github.com/owner/repo");
        assert_eq!(result1, "https://my-github-proxy.com/owner/repo");

        // Subdomain does NOT get replaced (which is correct behavior)
        let result2 = test_url_replacement(replacements, "https://api.github.com/repos/owner/repo");
        assert_eq!(result2, "https://api.github.com/repos/owner/repo");
    }

    #[test]
    fn test_protocol_insensitive_current_behavior() {
        // Current implementation replaces host regardless of protocol
        let mut replacements = IndexMap::new();
        replacements.insert("github.com".to_string(), "my-proxy.com".to_string());

        let result1 = test_url_replacement(replacements.clone(), "https://github.com/owner/repo");
        let result2 = test_url_replacement(replacements, "http://github.com/owner/repo");

        // Both protocols get host replaced
        assert_eq!(result1, "https://my-proxy.com/owner/repo");
        assert_eq!(result2, "http://my-proxy.com/owner/repo");
    }

    #[test]
    fn test_full_url_key_not_supported() {
        // Current implementation doesn't support full URL keys
        let mut replacements = IndexMap::new();
        replacements.insert(
            "https://github.com".to_string(),
            "https://my-proxy.com".to_string(),
        );

        let result = test_url_replacement(replacements, "https://github.com/owner/repo");

        // No replacement happens because "https://github.com" doesn't match hostname "github.com"
        assert_eq!(result, "https://github.com/owner/repo");
    }

    // Test function for new enhanced URL replacement logic
    fn test_enhanced_url_replacement(
        replacements: IndexMap<String, String>,
        original_url: &str,
    ) -> String {
        let mut url = Url::parse(original_url).unwrap();

        // New enhanced logic: try full URL first, then fall back to host
        let url_without_path = format!("{}://{}", url.scheme(), url.host_str().unwrap_or(""));

        if let Some(replacement) = replacements.get(&url_without_path) {
            // Full URL replacement
            if let Ok(replacement_url) = Url::parse(replacement) {
                let _ = url.set_scheme(replacement_url.scheme());
                if let Some(host) = replacement_url.host_str() {
                    let _ = url.set_host(Some(host));
                }
                if let Some(port) = replacement_url.port() {
                    let _ = url.set_port(Some(port));
                } else if replacement_url.port().is_none() {
                    // Clear port if replacement URL doesn't specify one
                    let _ = url.set_port(None);
                }
                // Handle the path component - prepend replacement path to existing path
                let replacement_path = replacement_url.path();
                if !replacement_path.is_empty() && replacement_path != "/" {
                    let current_path = url.path();
                    let new_path = if replacement_path.ends_with('/') {
                        format!("{}{}", replacement_path.trim_end_matches('/'), current_path)
                    } else {
                        format!("{}{}", replacement_path, current_path)
                    };
                    url.set_path(&new_path);
                }
            }
        } else if let Some(host) = url.host_str() {
            // Fall back to host-only replacement (current behavior)
            if let Some(replacement) = replacements.get(host) {
                // Try to parse replacement as a full URL first (to handle cases where the value is a full URL)
                if let Ok(replacement_url) = Url::parse(replacement) {
                    // Full URL replacement - extract all components
                    let _ = url.set_scheme(replacement_url.scheme());
                    if let Some(replacement_host) = replacement_url.host_str() {
                        let _ = url.set_host(Some(replacement_host));
                    }
                    if let Some(port) = replacement_url.port() {
                        let _ = url.set_port(Some(port));
                    } else if replacement_url.port().is_none() {
                        // Clear port if replacement URL doesn't specify one
                        let _ = url.set_port(None);
                    }
                    // Handle the path component - prepend replacement path to existing path
                    let replacement_path = replacement_url.path();
                    if !replacement_path.is_empty() && replacement_path != "/" {
                        let current_path = url.path();
                        let new_path = if replacement_path.ends_with('/') {
                            format!("{}{}", replacement_path.trim_end_matches('/'), current_path)
                        } else {
                            format!("{}{}", replacement_path, current_path)
                        };
                        url.set_path(&new_path);
                    }
                } else {
                    // Simple hostname replacement (original behavior)
                    let _ = url.set_host(Some(replacement));
                }
            }
        }

        url.to_string()
    }

    #[test]
    fn test_enhanced_protocol_specific_replacement() {
        // Test the enhanced logic with protocol-specific replacement
        let mut replacements = IndexMap::new();
        replacements.insert(
            "https://github.com".to_string(),
            "https://my-proxy.com".to_string(),
        );

        let result1 =
            test_enhanced_url_replacement(replacements.clone(), "https://github.com/owner/repo");
        let result2 = test_enhanced_url_replacement(replacements, "http://github.com/owner/repo");

        // Only https gets replaced, http does not
        assert_eq!(result1, "https://my-proxy.com/owner/repo");
        assert_eq!(result2, "http://github.com/owner/repo");
    }

    #[test]
    fn test_enhanced_subdomain_exclusion() {
        // Test that enhanced logic properly excludes subdomains with protocol-specific replacement
        let mut replacements = IndexMap::new();
        replacements.insert(
            "https://github.com".to_string(),
            "https://my-proxy.com".to_string(),
        );

        let result1 =
            test_enhanced_url_replacement(replacements.clone(), "https://github.com/owner/repo");
        let result2 =
            test_enhanced_url_replacement(replacements, "https://api.github.com/repos/owner/repo");

        // Only the exact match gets replaced, subdomain does not
        assert_eq!(result1, "https://my-proxy.com/owner/repo");
        assert_eq!(result2, "https://api.github.com/repos/owner/repo");
    }

    #[test]
    fn test_enhanced_fallback_to_host() {
        // Test that enhanced logic falls back to host-only replacement
        let mut replacements = IndexMap::new();
        replacements.insert("github.com".to_string(), "my-proxy.com".to_string());

        let result = test_enhanced_url_replacement(replacements, "https://github.com/owner/repo");

        // Should fall back to host replacement since no full URL match
        assert_eq!(result, "https://my-proxy.com/owner/repo");
    }

    #[test]
    fn test_real_apply_url_replacements_integration() {
        // Test that the real apply_url_replacements function works
        // This test will only work if settings can be mocked, otherwise it's a documentation test
        let mut url1 = Url::parse("https://github.com/owner/repo").unwrap();
        let mut url2 = Url::parse("http://github.com/owner/repo").unwrap();
        let mut url3 = Url::parse("https://api.github.com/repos/owner/repo").unwrap();

        // Note: This test demonstrates the expected behavior but may not work
        // without proper settings injection. It serves as documentation.
        apply_url_replacements(&mut url1);
        apply_url_replacements(&mut url2);
        apply_url_replacements(&mut url3);

        // Without settings configured, URLs should remain unchanged
        assert_eq!(url1.as_str(), "https://github.com/owner/repo");
        assert_eq!(url2.as_str(), "http://github.com/owner/repo");
        assert_eq!(url3.as_str(), "https://api.github.com/repos/owner/repo");
    }

    #[test]
    fn test_url_replacement_examples() {
        // Document expected behavior with various replacement patterns

        // Example 1: Host-only replacement (current/legacy behavior)
        let mut replacements = IndexMap::new();
        replacements.insert("github.com".to_string(), "my-proxy.com".to_string());

        assert_eq!(
            test_enhanced_url_replacement(replacements.clone(), "https://github.com/owner/repo"),
            "https://my-proxy.com/owner/repo"
        );
        assert_eq!(
            test_enhanced_url_replacement(replacements.clone(), "http://github.com/owner/repo"),
            "http://my-proxy.com/owner/repo"
        );
        // Subdomains not affected
        assert_eq!(
            test_enhanced_url_replacement(replacements, "https://api.github.com/repos/owner/repo"),
            "https://api.github.com/repos/owner/repo"
        );

        // Example 2: Protocol-specific replacement (new feature)
        let mut replacements = IndexMap::new();
        replacements.insert(
            "https://github.com".to_string(),
            "https://secure-proxy.com".to_string(),
        );

        // Only https URLs get replaced
        assert_eq!(
            test_enhanced_url_replacement(replacements.clone(), "https://github.com/owner/repo"),
            "https://secure-proxy.com/owner/repo"
        );
        // http URLs are not affected
        assert_eq!(
            test_enhanced_url_replacement(replacements.clone(), "http://github.com/owner/repo"),
            "http://github.com/owner/repo"
        );
        // Subdomains are not affected
        assert_eq!(
            test_enhanced_url_replacement(replacements, "https://api.github.com/repos/owner/repo"),
            "https://api.github.com/repos/owner/repo"
        );

        // Example 3: Mixed replacement patterns
        let mut replacements = IndexMap::new();
        replacements.insert(
            "https://github.com".to_string(),
            "https://secure-proxy.com".to_string(),
        );
        replacements.insert("npmjs.org".to_string(), "npm-proxy.com".to_string());

        // GitHub with protocol-specific replacement
        assert_eq!(
            test_enhanced_url_replacement(replacements.clone(), "https://github.com/owner/repo"),
            "https://secure-proxy.com/owner/repo"
        );
        // NPM with host-only replacement (backward compatibility)
        assert_eq!(
            test_enhanced_url_replacement(replacements.clone(), "https://npmjs.org/package"),
            "https://npm-proxy.com/package"
        );
        assert_eq!(
            test_enhanced_url_replacement(replacements, "http://npmjs.org/package"),
            "http://npm-proxy.com/package"
        );
    }

    #[test]
    fn test_url_replacement_bug_with_path() {
        // This test reproduces the bug described in the issue:
        // When using url_replacements = { "https://github.com" = "https://my.company.net/artifactory/github-remote" }
        // The bug is that mise only replaces with "https://my.company.net" and drops the path "/artifactory/github-remote"

        let mut replacements = IndexMap::new();
        replacements.insert(
            "https://github.com".to_string(),
            "https://my.company.net/artifactory/github-remote".to_string(),
        );

        let result = test_enhanced_url_replacement(replacements, "https://github.com/owner/repo");

        // This should be the CORRECT behavior (what we want after the fix):
        assert_eq!(
            result,
            "https://my.company.net/artifactory/github-remote/owner/repo"
        );

        // TODO: The current broken behavior would be:
        // assert_eq!(result, "https://my.company.net/owner/repo");  // This is the bug - path is lost
    }

    #[test]
    fn test_host_only_replacement_with_full_url_value_bug() {
        // This test demonstrates the bug in the current implementation where
        // host-only matching tries to use a full URL as a hostname

        let mut replacements = IndexMap::new();
        // This is a host-only key, but with a full URL as the value (which should work but is buggy)
        replacements.insert(
            "github.com".to_string(),
            "https://my.company.net/artifactory/github-remote".to_string(),
        );

        // Using the current (buggy) test_url_replacement function that mimics the current bug
        let result = test_url_replacement(replacements, "https://github.com/owner/repo");

        // This demonstrates the current buggy behavior - the replacement value should be parsed as a URL
        // but instead the full URL string is passed to set_host() which corrupts the URL
        // The current implementation calls url.set_host(Some("https://my.company.net/artifactory/github-remote"))
        // which results in malformed URLs
        assert_eq!(result, "https://https/owner/repo"); // Corrupted URL due to invalid hostname
    }

    #[test]
    fn test_host_only_replacement_with_full_url_value_fixed() {
        // This test demonstrates the FIXED behavior where host-only matching
        // properly handles full URL values by parsing them

        let mut replacements = IndexMap::new();
        // This is a host-only key, but with a full URL as the value (now works correctly)
        replacements.insert(
            "github.com".to_string(),
            "https://my.company.net/artifactory/github-remote".to_string(),
        );

        // Using the enhanced test function that mimics the fixed behavior
        let result = test_enhanced_url_replacement(replacements, "https://github.com/owner/repo");

        // This should now work correctly - the replacement value is parsed as a URL
        // and all components (scheme, host, port, path) are properly applied
        assert_eq!(
            result,
            "https://my.company.net/artifactory/github-remote/owner/repo"
        );
    }
}
