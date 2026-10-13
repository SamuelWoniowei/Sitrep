//! All network access lives here. The UI (webview) has no network access at
//! all: its Content Security Policy only allows talking to the Rust side.
//!
//! Rules enforced:
//! * Feeds: HTTPS only, fixed allowlist of hosts, redirects only to
//!   allowlisted HTTPS hosts, size and time limits, no cookies.
//! * Local AI: only http://127.0.0.1:11434 (Ollama), never a remote host.

use std::time::Duration;

use reqwest::{redirect, Client, Response};
use url::Url;

pub const MAX_FEED_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_AI_BYTES: usize = 512 * 1024;
const USER_AGENT: &str = "Sitrep/0.2 (+https://github.com/samuelwoniowei/sitrep)";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedKind {
    Rss,
    KevJson,
}

#[derive(Clone, Copy, Debug)]
pub struct Source {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub kind: FeedKind,
    pub uk: bool,
    /// General-news feeds: keep only items that look security-related.
    pub cyber_only: bool,
}

/// The only places Sitrep ever fetches from. Changing this list is a
/// security-relevant change: update docs/THREAT_MODEL.md too.
pub const SOURCES: &[Source] = &[
    Source {
        id: "bleeping",
        name: "BleepingComputer",
        url: "https://www.bleepingcomputer.com/feed/",
        kind: FeedKind::Rss,
        uk: false,
        cyber_only: false,
    },
    Source {
        id: "record",
        name: "The Record",
        url: "https://therecord.media/feed",
        kind: FeedKind::Rss,
        uk: false,
        cyber_only: false,
    },
    Source {
        id: "thn",
        name: "The Hacker News",
        url: "https://feeds.feedburner.com/TheHackersNews",
        kind: FeedKind::Rss,
        uk: false,
        cyber_only: false,
    },
    Source {
        id: "ncsc",
        name: "NCSC (UK)",
        url: "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml",
        kind: FeedKind::Rss,
        uk: true,
        cyber_only: false,
    },
    Source {
        id: "sans",
        name: "SANS ISC",
        url: "https://isc.sans.edu/rssfeed_full.xml",
        kind: FeedKind::Rss,
        uk: false,
        cyber_only: false,
    },
    Source {
        id: "cisa_adv",
        name: "CISA Advisories",
        url: "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        kind: FeedKind::Rss,
        uk: false,
        cyber_only: false,
    },
    Source {
        id: "msrc",
        name: "Microsoft MSRC",
        url: "https://api.msrc.microsoft.com/update-guide/rss",
        kind: FeedKind::Rss,
        uk: false,
        cyber_only: false,
    },
    Source {
        id: "talos",
        name: "Cisco Talos",
        url: "https://blog.talosintelligence.com/rss/",
        kind: FeedKind::Rss,
        uk: false,
        cyber_only: false,
    },
    Source {
        id: "krebs",
        name: "Krebs on Security",
        url: "https://krebsonsecurity.com/feed/",
        kind: FeedKind::Rss,
        uk: false,
        cyber_only: false,
    },
    Source {
        id: "bbc",
        name: "BBC News",
        url: "https://feeds.bbci.co.uk/news/technology/rss.xml",
        kind: FeedKind::Rss,
        uk: false,
        cyber_only: true,
    },
    Source {
        id: "kev",
        name: "CISA KEV",
        url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        kind: FeedKind::KevJson,
        uk: false,
        cyber_only: false,
    },
];

/// Hosts that feeds may redirect to (CDNs and canonical hosts).
const EXTRA_ALLOWED_HOSTS: &[&str] = &[
    "feeds.feedburner.com",
    "feeds.feedblitz.com",
    "bleepingcomputer.com",
];

/// The one host used for CVE severity lookups (NIST NVD API).
pub const NVD_HOST: &str = "services.nvd.nist.gov";

pub fn allowed_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    SOURCES
        .iter()
        .filter_map(|s| Url::parse(s.url).ok())
        .filter_map(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .any(|h| h == host)
        || EXTRA_ALLOWED_HOSTS.contains(&host.as_str())
}

/// Is this URL acceptable for the app to fetch?
pub fn fetchable(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.host_str().map(allowed_host).unwrap_or(false)
        && url.port().map(|p| p == 443).unwrap_or(true)
}

/// Is this URL acceptable to open in the user's browser? (Article links come
/// from feeds, so they are untrusted: only plain https links are allowed.)
pub fn openable(raw: &str) -> Option<Url> {
    let url = Url::parse(raw.trim()).ok()?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    // Only real domain names: no raw IPs (v4 or v6) and nothing local.
    match url.host()? {
        url::Host::Domain(d) => {
            let d = d.to_ascii_lowercase();
            if d.is_empty() || d == "localhost" || d.ends_with(".localhost") || !d.contains('.') {
                return None;
            }
        }
        _ => return None,
    }
    Some(url)
}

pub fn feed_client() -> reqwest::Result<Client> {
    Client::builder()
        .https_only(true)
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(25))
        .connect_timeout(Duration::from_secs(10))
        .redirect(redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 3 || !fetchable(attempt.url()) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
}

/// Full articles may only be fetched from these exact hosts: the sites whose
/// feeds Sitrep already reads. A link anywhere else is never fetched, only
/// opened in the browser if the user clicks "Read source".
pub const ARTICLE_HOSTS: &[&str] = &[
    "www.bleepingcomputer.com",
    "therecord.media",
    "thehackernews.com",
    "www.ncsc.gov.uk",
    "isc.sans.edu",
    "www.cisa.gov",
    "krebsonsecurity.com",
    "blog.talosintelligence.com",
];
pub const MAX_ARTICLE_BYTES: usize = 2 * 1024 * 1024;

pub fn article_fetchable(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().map(|p| p == 443).unwrap_or(true)
        && matches!(url.host(), Some(url::Host::Domain(d)) if ARTICLE_HOSTS.contains(&d.to_ascii_lowercase().as_str()))
}

pub fn article_client() -> reqwest::Result<Client> {
    Client::builder()
        .https_only(true)
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(20))
        .connect_timeout(Duration::from_secs(10))
        .redirect(redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 3 || !article_fetchable(attempt.url()) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
}

/// Fetch an article page. Only HTML from an allowlisted article host, capped
/// in size; anything else is refused.
pub async fn fetch_article(client: &Client, raw: &str) -> Result<Vec<u8>, String> {
    let url = Url::parse(raw).map_err(|e| e.to_string())?;
    if !article_fetchable(&url) {
        return Err("article host not allowed".into());
    }
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    if !article_fetchable(resp.url()) {
        return Err("redirected outside allowlist".into());
    }
    let html = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.to_ascii_lowercase().starts_with("text/html"))
        .unwrap_or(false);
    if !html {
        return Err("not an HTML page".into());
    }
    read_capped(resp, MAX_ARTICLE_BYTES).await
}

pub fn ai_client() -> reqwest::Result<Client> {
    Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(180))
        .connect_timeout(Duration::from_secs(3))
        .redirect(redirect::Policy::none())
        .build()
}

/// Read a response body without ever holding more than `max` bytes.
pub async fn read_capped(mut resp: Response, max: usize) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length() {
        if len as usize > max {
            return Err("response too large".into());
        }
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if buf.len() + chunk.len() > max {
            return Err("response too large".into());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

pub async fn fetch_source(client: &Client, src: &Source) -> Result<Vec<u8>, String> {
    let url = Url::parse(src.url).map_err(|e| e.to_string())?;
    if !fetchable(&url) {
        return Err("source not allowed".into());
    }
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    if !fetchable(resp.url()) {
        return Err("redirected outside allowlist".into());
    }
    read_capped(resp, MAX_FEED_BYTES).await
}

/// `CVE-YYYY-NNNN…` and nothing else. Used before an ID is placed in a URL.
pub fn valid_cve(id: &str) -> bool {
    let b = id.as_bytes();
    id.len() >= 13
        && id.len() <= 20
        && id.starts_with("CVE-")
        && b[8] == b'-'
        && b[4..8].iter().all(u8::is_ascii_digit)
        && b[9..].iter().all(u8::is_ascii_digit)
}

#[derive(Clone, Debug, PartialEq)]
pub struct Cvss {
    pub score: f64,
    pub severity: String,
}

/// Pull the best CVSS base score out of an NVD 2.0 response.
pub fn parse_nvd(bytes: &[u8]) -> Option<Cvss> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let metrics = v
        .get("vulnerabilities")?
        .get(0)?
        .get("cve")?
        .get("metrics")?;
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"] {
        if let Some(d) = metrics
            .get(key)
            .and_then(|m| m.get(0))
            .and_then(|m| m.get("cvssData"))
        {
            let score = d.get("baseScore")?.as_f64()?;
            if !(0.0..=10.0).contains(&score) {
                return None;
            }
            let sev = match d.get("baseSeverity").and_then(|s| s.as_str()).unwrap_or("") {
                s @ ("LOW" | "MEDIUM" | "HIGH" | "CRITICAL") => s.to_string(),
                _ => severity_for(score).to_string(),
            };
            return Some(Cvss {
                score,
                severity: sev,
            });
        }
    }
    None
}

pub fn severity_for(score: f64) -> &'static str {
    match score {
        s if s >= 9.0 => "CRITICAL",
        s if s >= 7.0 => "HIGH",
        s if s >= 4.0 => "MEDIUM",
        _ => "LOW",
    }
}

/// Look up one CVE's severity on NVD. The ID is validated, the host is fixed,
/// the response is size-capped and only a number and a label are kept.
pub async fn fetch_cvss(client: &Client, cve: &str) -> Result<Option<Cvss>, String> {
    if !valid_cve(cve) {
        return Err("invalid CVE id".into());
    }
    let url = Url::parse(&format!(
        "https://{NVD_HOST}/rest/json/cves/2.0?cveId={cve}"
    ))
    .map_err(|e| e.to_string())?;
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if resp.url().host_str() != Some(NVD_HOST) {
        return Err("redirected outside allowlist".into());
    }
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    Ok(parse_nvd(&read_capped(resp, 1024 * 1024).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_ids_are_validated() {
        for ok in ["CVE-2026-1234", "CVE-2024-12345678", "CVE-2025-0001"] {
            assert!(valid_cve(ok), "{ok}");
        }
        for bad in [
            "",
            "cve-2026-1234",
            "CVE-2026-12",
            "CVE-2026-1234&x=1",
            "CVE-2026-1234/../..",
            "CVE-20X6-1234",
            "CVE-2026-1234 ",
            "CVE-2026-123456789012",
        ] {
            assert!(!valid_cve(bad), "{bad}");
        }
    }

    #[test]
    fn nvd_response_parsed_and_bounded() {
        let ok = br#"{"vulnerabilities":[{"cve":{"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}}]}"#;
        assert_eq!(
            parse_nvd(ok),
            Some(Cvss {
                score: 9.8,
                severity: "CRITICAL".into()
            })
        );
        let weird = br#"{"vulnerabilities":[{"cve":{"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"baseSeverity":"<script>"}}]}}}]}"#;
        assert_eq!(parse_nvd(weird).unwrap().severity, "HIGH");
        let huge = br#"{"vulnerabilities":[{"cve":{"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":99.0}}]}}}]}"#;
        assert!(parse_nvd(huge).is_none());
        assert!(parse_nvd(b"not json").is_none());
        assert!(parse_nvd(b"{}").is_none());
    }

    #[tokio::test]
    async fn nvd_lookup_rejects_bad_ids_without_network() {
        let c = feed_client().unwrap();
        assert!(fetch_cvss(&c, "CVE-2026-1234&evil=1").await.is_err());
    }

    #[test]
    fn allowlist_accepts_sources_only() {
        for s in SOURCES {
            assert!(fetchable(&Url::parse(s.url).unwrap()), "{}", s.url);
        }
        for bad in [
            "http://www.bleepingcomputer.com/feed/",
            "https://evil.example/feed",
            "https://www.bleepingcomputer.com.evil.example/",
            "https://user:pw@therecord.media/feed",
            "https://therecord.media:8443/feed",
            "file:///etc/passwd",
            "https://127.0.0.1/",
        ] {
            assert!(!fetchable(&Url::parse(bad).unwrap()), "{bad}");
        }
    }

    /// Serve one canned HTTP response on a random local port.
    async fn serve_once(response: Vec<u8>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(&response).await;
                let _ = sock.shutdown().await;
            }
        });
        format!("http://{addr}/")
    }

    #[tokio::test]
    async fn oversized_bodies_are_cut_off() {
        // A hostile server streams far more than allowed, without Content-Length.
        let mut resp = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
        resp.extend(std::iter::repeat(b'A').take(MAX_AI_BYTES * 3));
        let url = serve_once(resp).await;
        let r = ai_client().unwrap().get(url).send().await.unwrap();
        assert!(read_capped(r, MAX_AI_BYTES).await.is_err());
    }

    #[tokio::test]
    async fn lying_content_length_rejected_early() {
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\nshort",
            MAX_FEED_BYTES * 10
        )
        .into_bytes();
        let url = serve_once(resp).await;
        let r = ai_client().unwrap().get(url).send().await.unwrap();
        assert!(read_capped(r, MAX_FEED_BYTES).await.is_err());
    }

    #[tokio::test]
    async fn ai_client_never_follows_redirects() {
        let resp = b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
        let url = serve_once(resp).await;
        let r = ai_client().unwrap().get(url).send().await.unwrap();
        assert_eq!(r.status().as_u16(), 302, "redirect must not be followed");
    }

    #[tokio::test]
    async fn feed_client_refuses_plain_http() {
        let url = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()).await;
        assert!(feed_client().unwrap().get(url).send().await.is_err());
    }

    #[tokio::test]
    async fn fetch_source_rejects_non_allowlisted_source() {
        let fake = Source {
            id: "x",
            name: "Evil",
            url: "https://evil.example/feed",
            kind: FeedKind::Rss,
            uk: false,
            cyber_only: false,
        };
        let err = fetch_source(&feed_client().unwrap(), &fake)
            .await
            .unwrap_err();
        assert_eq!(err, "source not allowed");
    }

    #[test]
    fn article_allowlist_is_strict() {
        for ok in [
            "https://www.bleepingcomputer.com/news/security/x/",
            "https://therecord.media/some-story",
            "https://thehackernews.com/2026/10/x.html",
            "https://www.ncsc.gov.uk/news/x",
            "https://isc.sans.edu/diary/12345",
            "https://www.cisa.gov/news-events/alerts/x",
            "https://krebsonsecurity.com/2026/10/x/",
            "https://blog.talosintelligence.com/x/",
        ] {
            assert!(article_fetchable(&Url::parse(ok).unwrap()), "{ok}");
        }
        for bad in [
            "http://therecord.media/x",
            "https://evil.example/x",
            "https://therecord.media.evil.example/x",
            "https://evil-therecord.media/x",
            "https://user:pw@therecord.media/x",
            "https://therecord.media:8443/x",
            "https://feeds.feedburner.com/x",
            "https://cisa.gov.evil.example/x",
            "https://services.nvd.nist.gov/x",
            "https://127.0.0.1/x",
            "https://[::1]/x",
        ] {
            assert!(!article_fetchable(&Url::parse(bad).unwrap()), "{bad}");
        }
    }

    #[tokio::test]
    async fn fetch_article_refuses_other_hosts() {
        let c = article_client().unwrap();
        assert_eq!(
            fetch_article(&c, "https://evil.example/a")
                .await
                .unwrap_err(),
            "article host not allowed"
        );
        assert!(fetch_article(&c, "javascript:alert(1)").await.is_err());
    }

    #[test]
    fn openable_links() {
        assert!(openable("https://www.bleepingcomputer.com/news/x/").is_some());
        for bad in [
            "javascript:alert(1)",
            "http://example.com",
            "file:///C:/Windows/System32/calc.exe",
            "https://localhost/x",
            "https://127.0.0.1/x",
            "https://[::1]/x",
            "https://user:pass@example.com",
            "data:text/html,<script>alert(1)</script>",
            "ms-msdt:/id PCWDiagnostic",
            "smb://evil/share",
            "",
        ] {
            assert!(openable(bad).is_none(), "{bad}");
        }
    }
}
