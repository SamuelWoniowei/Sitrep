//! Text hygiene. Everything that comes from the network (feeds, AI output)
//! passes through here and leaves as plain text: no HTML, no control
//! characters, bounded length. The UI never renders HTML, so this is the
//! first of two layers against injected markup.

use scraper::{ElementRef, Html, Node};

/// Elements whose text content must never reach the user.
const DROP_ELEMENTS: &[&str] = &[
    "script", "style", "noscript", "iframe", "object", "embed", "template", "svg", "math",
];

/// Convert an HTML (or plain text) fragment to clean plain text.
pub fn to_plain(input: &str, max_chars: usize) -> String {
    // Parse as an HTML fragment so entities are decoded and tags removed.
    let fragment = Html::parse_fragment(input);
    let mut out = String::with_capacity(input.len().min(max_chars * 2));
    collect_text(fragment.root_element(), &mut out);
    let cleaned = clean_whitespace(&strip_controls(&out));
    truncate_chars(&cleaned, max_chars)
}

fn collect_text(el: ElementRef, out: &mut String) {
    for child in el.children() {
        match child.value() {
            Node::Text(t) => {
                out.push_str(t);
            }
            Node::Element(e) => {
                let name = e.name().to_ascii_lowercase();
                if DROP_ELEMENTS.contains(&name.as_str()) {
                    continue;
                }
                if let Some(child_el) = ElementRef::wrap(child) {
                    collect_text(child_el, out);
                }
                // Block-level boundaries become spaces so words don't merge.
                out.push(' ');
            }
            _ => {}
        }
    }
}

/// Remove control and invisible formatting characters (including bidi
/// overrides, which can be used to disguise text).
pub fn strip_controls(s: &str) -> String {
    s.chars()
        .filter(|c| {
            let cp = *c as u32;
            let is_bidi = matches!(cp, 0x202A..=0x202E | 0x2066..=0x2069 | 0x200E | 0x200F);
            let is_zero_width = matches!(cp, 0x200B..=0x200D | 0xFEFF);
            (!c.is_control() || *c == '\n' || *c == '\t') && !is_bidi && !is_zero_width
        })
        .collect()
}

pub fn clean_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
    t = t.trim_end().to_string();
    t.push('…');
    t
}

/// First `n` sentences of a plain-text string (best effort).
pub fn first_sentences(s: &str, n: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        out.push(chars[i]);
        if matches!(chars[i], '.' | '!' | '?')
            && (i + 1 == chars.len() || chars[i + 1].is_whitespace())
        {
            count += 1;
            if count >= n {
                break;
            }
        }
        i += 1;
    }
    out.trim().to_string()
}

/// Normalised token set used for de-duplicating near-identical headlines.
pub fn title_tokens(title: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "the", "a", "an", "of", "to", "in", "on", "for", "and", "with", "by", "is", "are", "as",
        "at", "from", "new", "after", "over",
    ];
    let mut v: Vec<String> = title
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 1 && !STOP.contains(w))
        .map(|w| w.to_string())
        .collect();
    v.sort();
    v.dedup();
    v
}

pub fn jaccard(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let inter = a.iter().filter(|x| b.contains(x)).count() as f64;
    let union = (a.len() + b.len()) as f64 - inter;
    inter / union
}

pub const MAX_ARTICLE_CHARS: usize = 6000;

/// Pull the readable body text out of a news article page: the paragraphs
/// inside <article> (or <main>, or the whole page as a last resort), with
/// scripts, navigation, forms and short boilerplate lines dropped. Returns
/// plain text only.
pub fn extract_article(html: &str) -> String {
    let doc = Html::parse_document(html);
    let mut paras: Vec<String> = Vec::new();
    for scope in ["article p", "main p", "p"] {
        let sel = scraper::Selector::parse(scope).expect("static selector");
        paras = doc
            .select(&sel)
            .filter(|p| {
                // Skip paragraphs that sit inside page furniture.
                !p.ancestors().any(|a| {
                    a.value().as_element().is_some_and(|e| {
                        matches!(
                            e.name(),
                            "nav"
                                | "footer"
                                | "header"
                                | "aside"
                                | "form"
                                | "noscript"
                                | "script"
                                | "style"
                        )
                    })
                })
            })
            .map(|p| {
                let mut s = String::new();
                collect_text(p, &mut s);
                clean_whitespace(&strip_controls(&s))
            })
            .filter(|t| t.chars().count() >= 40)
            .collect();
        if paras.iter().map(|p| p.len()).sum::<usize>() >= 400 {
            break;
        }
    }
    let mut out = String::new();
    for p in paras {
        if out.chars().count() + p.chars().count() > MAX_ARTICLE_CHARS {
            break;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn article_extraction_keeps_body_drops_junk() {
        let para =
            "Attackers exploited a flaw in a widely used VPN product to break into networks.";
        let html = format!(
            r#"<html><head><script>steal()</script><style>p{{}}</style></head><body>
            <header><p>Subscribe to our newsletter for daily updates and offers today</p></header>
            <nav><p>Home News Security Cloud Malware Ransomware Deals Contact</p></nav>
            <article><p>{para}</p><p>Short.</p><p>{para} <script>alert(1)</script><img src=x onerror=alert(1)></p>
            <p>The vendor released a patch and urged customers to update immediately to the fixed version.</p>
            <p>{para}</p><p>{para}</p><p>{para}</p></article>
            <footer><p>Copyright notice and legal links that are long enough to count as a paragraph.</p></footer>
            </body></html>"#
        );
        let t = extract_article(&html);
        assert!(t.contains("The vendor released a patch"));
        assert!(!t.contains("newsletter") && !t.contains("Copyright") && !t.contains("Short."));
        assert!(!t.contains('<') && !t.contains("alert") && !t.contains("steal"));
    }

    #[test]
    fn article_extraction_is_capped() {
        let p = format!("<p>{}</p>", "word ".repeat(200));
        let html = format!("<article>{}</article>", p.repeat(500));
        assert!(extract_article(&html).chars().count() <= MAX_ARTICLE_CHARS);
    }

    #[test]
    fn strips_tags_and_scripts() {
        let s = to_plain(
            r#"<p>Hello <b>world</b></p><script>alert(1)</script><img src=x onerror=alert(1)>"#,
            500,
        );
        assert_eq!(s, "Hello world");
        assert!(!s.contains('<'));
        assert!(!s.contains("alert"));
    }

    #[test]
    fn decodes_entities_but_output_is_plain() {
        let s = to_plain("&lt;script&gt;alert(1)&lt;/script&gt; &amp; more", 500);
        // The literal text is kept, but it is only ever rendered as text.
        assert_eq!(s, "<script>alert(1)</script> & more");
    }

    #[test]
    fn drops_style_svg_iframe_contents() {
        let s = to_plain(
            "<style>body{}</style><svg><script>x()</script></svg><iframe>bad</iframe>ok",
            500,
        );
        assert_eq!(s, "ok");
    }

    #[test]
    fn removes_bidi_and_zero_width() {
        let s = to_plain("safe\u{202E}gpj.exe\u{200B}x\u{0007}", 500);
        assert_eq!(s, "safegpj.exex");
    }

    #[test]
    fn truncates_by_chars_not_bytes() {
        let s = to_plain("ééééééééé", 4);
        assert_eq!(s.chars().count(), 4);
    }

    #[test]
    fn sentences() {
        assert_eq!(first_sentences("One. Two! Three?", 2), "One. Two!");
        assert_eq!(
            first_sentences("v1.2 is out. Patch now.", 1),
            "v1.2 is out."
        );
    }

    #[test]
    fn dedupe_similarity() {
        let a = title_tokens("Fortinet warns of new FortiGate zero-day exploited in attacks");
        let b = title_tokens("FortiGate zero-day exploited in attacks, Fortinet warns");
        assert!(jaccard(&a, &b) > 0.6);
        let c = title_tokens("Microsoft October Patch Tuesday fixes 80 flaws");
        assert!(jaccard(&a, &c) < 0.2);
    }
}
