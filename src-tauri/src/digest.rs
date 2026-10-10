//! The weekly digest: a clean, shareable page (and plain text for pasting into
//! LinkedIn) built from the last 7 days of stories. Built locally; nothing is
//! uploaded. Every story-derived string is HTML-escaped, and the page carries a
//! Content-Security-Policy that forbids scripts and any network access.

use serde::Serialize;

use crate::core::{self, week_key};
use crate::intel;
use crate::store::Store;
use crate::text::to_plain;
use crate::themes::Category;

const DAY: i64 = 86_400;
const TOP: usize = 5;

#[derive(Serialize, Clone, Debug)]
pub struct WeeklyDigest {
    pub week: String,
    pub stories: usize,
    #[serde(skip)]
    pub html: String,
    pub markdown: String,
}

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c if c.is_control() && c != '\n' => {}
            c => o.push(c),
        }
    }
    o
}

fn rank(c: &Category) -> u8 {
    match c {
        Category::ExploitedNow => 0,
        Category::BigIncident => 1,
        Category::Uk => 2,
        Category::News => 3,
    }
}

/// Only plain https links are ever written into the page.
fn safe_link(l: &str) -> Option<String> {
    let u = url::Url::parse(l).ok()?;
    (u.scheme() == "https" && u.host_str().is_some()).then(|| u.to_string())
}

struct Item {
    label: String,
    headline: String,
    tldr: String,
    why: String,
    source: String,
    link: Option<String>,
}

pub fn build(store: &Store, now: i64, author: &str) -> WeeklyDigest {
    let week = week_key(now);
    let author = to_plain(author, 30);
    let rows = store.stories_since(now - 7 * DAY).unwrap_or_default();
    let total = rows.len();
    let mut ranked: Vec<_> = rows
        .iter()
        .map(|r| (rank(&core::category_of(store, r)), r))
        .collect();
    ranked.sort_by_key(|(k, r)| (*k, std::cmp::Reverse(r.published)));
    let items: Vec<Item> = ranked
        .into_iter()
        .take(TOP)
        .map(|(_, r)| {
            let c = core::story_card(store, r, &[], false);
            Item {
                label: c.category_label.to_string(),
                headline: to_plain(&c.headline, 160),
                tldr: to_plain(&c.tldr, 300),
                why: to_plain(&c.why, 300),
                source: c.sources.first().cloned().unwrap_or_default(),
                link: r.link.as_deref().and_then(safe_link),
            }
        })
        .collect();

    let since = chrono::DateTime::from_timestamp(now - 7 * DAY, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default();
    let exploited = store.kev_recent(&since).map(|v| v.len()).unwrap_or(0);
    let recap = core::recap(store, now);
    let actors = intel::actors_seen(store, now - 7 * DAY);
    let developing = intel::clusters(store, &Default::default(), now - 7 * DAY).len();

    // ---------- plain text (for pasting) ----------
    let mut md = format!("Sitrep weekly digest, {week}\n\n");
    md.push_str(&format!(
        "{total} stories read through, {exploited} newly exploited flaws added to CISA's list, {developing} developing stories.\n\n"
    ));
    for (i, it) in items.iter().enumerate() {
        md.push_str(&format!(
            "{}. {} ({})\n   {}\n   Why it matters: {}\n",
            i + 1,
            it.headline,
            it.label,
            it.tldr,
            it.why
        ));
        if let Some(l) = &it.link {
            md.push_str(&format!("   {l}\n"));
        }
        md.push('\n');
    }
    if !recap.themes.is_empty() {
        let t: Vec<String> = recap
            .themes
            .iter()
            .map(|t| format!("{} ({})", t.theme, t.count))
            .collect();
        md.push_str(&format!("Themes: {}\n", t.join(", ")));
    }
    if !actors.is_empty() {
        let a: Vec<&str> = actors.iter().take(5).map(|a| a.name).collect();
        md.push_str(&format!("Threat actors in the news: {}\n", a.join(", ")));
    }
    md.push_str("\nSummaries are automated. Check the sources before acting.\n#cybersecurity #infosec #threatintel\n");

    // ---------- page ----------
    let mut h = String::new();
    h.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    h.push_str("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    h.push_str(&format!(
        "<title>Sitrep weekly digest {}</title>",
        esc(&week)
    ));
    h.push_str("<style>body{margin:0;background:#0b1118;color:#dbe3ec;font:16px/1.55 system-ui,Segoe UI,sans-serif}main{max-width:760px;margin:0 auto;padding:40px 20px}h1{margin:0 0 4px;font-size:28px;color:#fff}.sub{color:#8a97a8;font-size:14px;margin-bottom:24px}.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px}.stat{flex:1 1 140px;border:1px solid #243042;border-radius:10px;padding:12px 14px;background:#101922}.stat b{display:block;font-size:26px;color:#38d39f}.item{border-top:1px solid #243042;padding:18px 0}.tag{display:inline-block;font:12px monospace;padding:2px 8px;border-radius:4px;background:#1e2733;color:#9be8c8}.item h2{margin:8px 0 6px;font-size:19px;color:#fff}.why{color:#aab6c4;font-size:15px}.src{font-size:13px;color:#8a97a8}a{color:#7cc4ff}h3{margin:28px 0 8px;font:12px monospace;letter-spacing:.1em;color:#8a97a8}footer{margin-top:36px;border-top:1px solid #243042;padding-top:14px;color:#8a97a8;font-size:13px}@media print{body{background:#fff;color:#111}h1,.item h2{color:#000}.stat{background:#fff}}</style></head><body><main>");
    h.push_str("<h1>Sitrep weekly digest</h1>");
    h.push_str(&format!(
        "<div class=\"sub\">{}{}</div>",
        esc(&week),
        if author.is_empty() {
            String::new()
        } else {
            format!(" · compiled by {}", esc(&author))
        }
    ));
    h.push_str(&format!(
        "<div class=\"stats\"><div class=\"stat\"><b>{total}</b>stories read through</div><div class=\"stat\"><b>{exploited}</b>exploited flaws added</div><div class=\"stat\"><b>{developing}</b>developing stories</div></div>"
    ));
    h.push_str("<h3>TOP STORIES</h3>");
    for it in &items {
        h.push_str(&format!(
            "<div class=\"item\"><span class=\"tag\">{}</span><h2>{}</h2><div>{}</div><div class=\"why\"><b>Why it matters:</b> {}</div><div class=\"src\">{}",
            esc(&it.label), esc(&it.headline), esc(&it.tldr), esc(&it.why), esc(&it.source)
        ));
        if let Some(l) = &it.link {
            h.push_str(&format!(
                " · <a href=\"{}\" rel=\"noopener noreferrer nofollow\">source</a>",
                esc(l)
            ));
        }
        h.push_str("</div></div>");
    }
    if !recap.themes.is_empty() {
        h.push_str("<h3>THEMES</h3><ul>");
        for t in &recap.themes {
            h.push_str(&format!(
                "<li><b>{}</b> · {} stories</li>",
                esc(&t.theme),
                t.count
            ));
        }
        h.push_str("</ul>");
    }
    if !actors.is_empty() {
        h.push_str("<h3>THREAT ACTORS IN THE NEWS</h3><ul>");
        for a in actors.iter().take(5) {
            h.push_str(&format!(
                "<li><b>{}</b> · {}</li>",
                esc(a.name),
                esc(a.blurb)
            ));
        }
        h.push_str("</ul>");
    }
    h.push_str("<footer>Made with Sitrep, a private desktop app. Summaries are automated: check the linked sources before acting on anything.</footer></main></body></html>");

    WeeklyDigest {
        week,
        stories: items.len(),
        html: h,
        markdown: md,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::RawItem;

    #[test]
    fn escapes_everything_hostile() {
        assert_eq!(
            esc("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(esc("a\"b'c&d"), "a&quot;b&#39;c&amp;d");
        assert_eq!(esc("x\u{0}y\u{1b}z"), "xyz");
    }

    #[test]
    fn only_https_links() {
        assert!(safe_link("https://example.org/a?b=c").is_some());
        assert!(safe_link("javascript:alert(1)").is_none());
        assert!(safe_link("http://example.org/").is_none());
        assert!(safe_link("data:text/html,<b>").is_none());
    }

    #[test]
    fn digest_page_is_inert() {
        let st = Store::open_in_memory().unwrap();
        let now = 1_791_500_000;
        let mk = |t: &str, link: &str| RawItem {
            title: t.into(),
            link: Some(link.into()),
            summary: "<img src=x onerror=alert(1)> CVE-2026-1".into(),
            published: now - 1000,
            source_id: "s".into(),
            source_name: "<b>S</b>".into(),
            cves: vec![],
        };
        st.upsert_items(
            &[
                mk(
                    "<script>alert(1)</script> flaw exploited",
                    "https://example.org/1",
                ),
                mk("Second story", "javascript:alert(1)"),
            ],
            now,
        )
        .unwrap();
        let d = build(&st, now, "<i>Sam</i>");
        assert!(d.html.contains("Content-Security-Policy"));
        assert!(!d.html.contains("<script>alert"));
        assert!(!d.html.contains("<img src=x"));
        assert!(!d.html.contains("javascript:"));
        assert!(!d.html.contains("<i>Sam</i>"));
        assert!(d.markdown.contains("Sitrep weekly digest"));
        assert!(d.stories >= 1);
    }
}
