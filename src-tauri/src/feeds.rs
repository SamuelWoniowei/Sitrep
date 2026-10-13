//! Parsing untrusted feed content into clean, bounded records.

use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;

use crate::net::{openable, Source};
use crate::text::{to_plain, truncate_chars};

pub const MAX_ITEMS_PER_FEED: usize = 100;
pub const MAX_TITLE: usize = 300;
pub const MAX_SUMMARY: usize = 4000;

/// BBC's technology feed is general news; only security stories are kept.
static CYBER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(cyber|hack(s|er|ers|ed|ing)?|ransomware|malware|spyware|botnet|phishing|data (breach|leak|theft)|breach(ed|es)?|vulnerabilit|exploit(ed|s)?|ddos|zero-day|infostealer|stolen data|encryption|cybercrim)")
        .expect("valid regex")
});

static CVE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bCVE-(\d{4})-(\d{4,7})\b").unwrap());

#[derive(Debug, Clone)]
pub struct RawItem {
    pub title: String,
    pub link: Option<String>,
    pub summary: String,
    pub published: i64,
    pub source_id: String,
    pub source_name: String,
    pub cves: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KevEntry {
    pub cve: String,
    pub vendor: String,
    pub product: String,
    pub name: String,
    pub date_added: String,
    pub description: String,
    pub ransomware: bool,
}

pub fn extract_cves(text: &str) -> Vec<String> {
    let mut v: Vec<String> = CVE_RE
        .captures_iter(text)
        .map(|c| format!("CVE-{}-{}", &c[1], &c[2]))
        .collect();
    v.sort();
    v.dedup();
    v.truncate(20);
    v
}

pub fn parse_rss(bytes: &[u8], src: &Source, now: i64) -> Result<Vec<RawItem>, String> {
    // feed-rs uses quick-xml, which does not resolve external entities or
    // expand custom DTD entities, so XXE and "billion laughs" do not apply.
    let feed = feed_rs::parser::parse(bytes).map_err(|e| format!("parse error: {e}"))?;
    let mut items = Vec::new();
    for entry in feed.entries.into_iter().take(MAX_ITEMS_PER_FEED) {
        let title = entry
            .title
            .map(|t| to_plain(&t.content, MAX_TITLE))
            .unwrap_or_default();
        if title.is_empty() {
            continue;
        }
        let raw_summary = entry
            .summary
            .map(|s| s.content)
            .or_else(|| entry.content.and_then(|c| c.body))
            .unwrap_or_default();
        let summary = crate::text::strip_feed_boilerplate(&to_plain(&raw_summary, MAX_SUMMARY));
        let link = entry
            .links
            .iter()
            .find_map(|l| openable(&l.href))
            .map(|u| u.to_string());
        let published = entry
            .published
            .or(entry.updated)
            .map(|d| d.timestamp())
            .unwrap_or(now)
            .min(now); // never trust future dates
        if src.cyber_only && !CYBER_RE.is_match(&format!("{title} {summary}")) {
            continue;
        }
        let cves = extract_cves(&format!("{title} {summary}"));
        items.push(RawItem {
            title,
            link,
            summary,
            published,
            source_id: src.id.to_string(),
            source_name: src.name.to_string(),
            cves,
        });
    }
    Ok(items)
}

#[derive(Deserialize)]
struct KevFile {
    vulnerabilities: Vec<KevRaw>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KevRaw {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(default)]
    vendor_project: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    vulnerability_name: String,
    #[serde(default)]
    date_added: String,
    #[serde(default)]
    short_description: String,
    #[serde(default)]
    known_ransomware_campaign_use: String,
}

pub fn parse_kev(bytes: &[u8]) -> Result<Vec<KevEntry>, String> {
    let file: KevFile = serde_json::from_slice(bytes).map_err(|e| format!("kev parse: {e}"))?;
    let mut out = Vec::new();
    for v in file.vulnerabilities.into_iter().take(5000) {
        let Some(cve) = extract_cves(&v.cve_id).into_iter().next() else {
            continue;
        };
        out.push(KevEntry {
            cve,
            vendor: to_plain(&v.vendor_project, 80),
            product: to_plain(&v.product, 120),
            name: to_plain(&v.vulnerability_name, 200),
            date_added: truncate_chars(
                &v.date_added
                    .chars()
                    .filter(|c| c.is_ascii_digit() || *c == '-')
                    .collect::<String>(),
                10,
            ),
            description: to_plain(&v.short_description, 600),
            ransomware: v
                .known_ransomware_campaign_use
                .eq_ignore_ascii_case("known"),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{FeedKind, Source};

    const SRC: Source = Source {
        id: "t",
        name: "Test",
        url: "https://therecord.media/feed",
        kind: FeedKind::Rss,
        uk: false,
        cyber_only: false,
    };
    const NOW: i64 = 1_800_000_000;

    fn rss(items: &str) -> Vec<u8> {
        format!(r#"<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>{items}</channel></rss>"#).into_bytes()
    }

    #[test]
    fn parses_and_sanitises_items() {
        let bytes = rss(
            r#"<item><title>&lt;b&gt;Big&lt;/b&gt; flaw CVE-2026-12345</title>
            <link>https://therecord.media/x</link>
            <description><![CDATA[<p>Attackers <script>steal()</script>exploit it.</p><img src=x onerror=alert(1)>]]></description>
            <pubDate>Fri, 09 Oct 2026 07:00:00 GMT</pubDate></item>"#,
        );
        let items = parse_rss(&bytes, &SRC, NOW).unwrap();
        assert_eq!(items.len(), 1);
        let it = &items[0];
        assert_eq!(it.title, "Big flaw CVE-2026-12345");
        assert_eq!(it.summary, "Attackers exploit it.");
        assert_eq!(it.cves, vec!["CVE-2026-12345"]);
        assert_eq!(it.link.as_deref(), Some("https://therecord.media/x"));
    }

    #[test]
    fn general_news_feeds_keep_only_security_stories() {
        let bbc = Source {
            cyber_only: true,
            ..SRC
        };
        let bytes = rss(
            r#"<item><title>Hackers take over thousands of smart fridges in France</title><link>https://www.bbc.co.uk/news/a</link></item>
            <item><title>New phone launch draws crowds</title><link>https://www.bbc.co.uk/news/b</link></item>
            <item><title>Shop chain confirms data breach</title><link>https://www.bbc.co.uk/news/c</link></item>
            <item><title>Chip maker posts record sales</title><link>https://www.bbc.co.uk/news/d</link><description>Shares rose.</description></item>"#,
        );
        let kept = parse_rss(&bytes, &bbc, NOW).unwrap();
        assert_eq!(kept.len(), 2);
        assert!(kept[0].title.contains("fridges") && kept[1].title.contains("breach"));
        assert_eq!(parse_rss(&bytes, &SRC, NOW).unwrap().len(), 4);
    }

    #[test]
    fn rejects_dangerous_links() {
        for link in [
            "javascript:alert(1)",
            "file:///C:/x.exe",
            "http://insecure.example/",
            "https://127.0.0.1/",
        ] {
            let bytes = rss(&format!("<item><title>x</title><link>{link}</link></item>"));
            let items = parse_rss(&bytes, &SRC, NOW).unwrap();
            assert_eq!(items[0].link, None, "{link}");
        }
    }

    #[test]
    fn xxe_is_not_resolved() {
        let bytes = br#"<?xml version="1.0"?>
<!DOCTYPE rss [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<rss version="2.0"><channel><title>t</title><item><title>a &xxe; b</title></item></channel></rss>"#;
        // Either the parser rejects it, or the entity is left unexpanded.
        if let Ok(items) = parse_rss(bytes, &SRC, NOW) {
            for it in items {
                assert!(!it.title.contains("root:"), "XXE expanded: {}", it.title);
            }
        }
    }

    #[test]
    fn billion_laughs_does_not_explode() {
        let bytes = br#"<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">]>
<rss version="2.0"><channel><title>t</title><item><title>&lol4;</title></item></channel></rss>"#;
        let start = std::time::Instant::now();
        if let Ok(items) = parse_rss(bytes, &SRC, NOW) {
            for it in items {
                assert!(it.title.len() <= MAX_TITLE * 4);
            }
        }
        assert!(start.elapsed().as_secs() < 2);
    }

    #[test]
    fn caps_items_and_lengths() {
        let long = "A".repeat(50_000);
        let many: String = (0..500)
            .map(|i| {
                format!("<item><title>t{i} {long}</title><description>{long}</description></item>")
            })
            .collect();
        let items = parse_rss(&rss(&many), &SRC, NOW).unwrap();
        assert_eq!(items.len(), MAX_ITEMS_PER_FEED);
        assert!(items
            .iter()
            .all(|i| i.title.chars().count() <= MAX_TITLE
                && i.summary.chars().count() <= MAX_SUMMARY));
    }

    #[test]
    fn future_dates_clamped() {
        let bytes =
            rss("<item><title>x</title><pubDate>Fri, 01 Jan 2100 00:00:00 GMT</pubDate></item>");
        assert_eq!(parse_rss(&bytes, &SRC, NOW).unwrap()[0].published, NOW);
    }

    #[test]
    fn garbage_is_an_error_not_a_crash() {
        assert!(parse_rss(b"\x00\xff not xml at all <<<", &SRC, NOW).is_err());
        assert!(parse_kev(b"{\"vulnerabilities\": 5}").is_err());
    }

    #[test]
    fn kev_parsing_validates_ids() {
        let json = br#"{"vulnerabilities":[
          {"cveID":"CVE-2026-1111","vendorProject":"Acme<script>","product":"VPN","vulnerabilityName":"RCE","dateAdded":"2026-10-08","shortDescription":"Bad","knownRansomwareCampaignUse":"Known"},
          {"cveID":"'; DROP TABLE kev;--","vendorProject":"x"}]}"#;
        let v = parse_kev(json).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].cve, "CVE-2026-1111");
        assert_eq!(v[0].vendor, "Acme");
        assert!(v[0].ransomware);
    }
}
