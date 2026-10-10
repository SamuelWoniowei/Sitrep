//! Log hunt: scan a log file the user picks for indicators (IPs, domains,
//! hashes) taken from recent security stories. Entirely local and read-only:
//! the file is chosen in a native dialog, streamed once, never copied, never
//! uploaded, and only short, sanitised sample lines leave this module.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::intel::extract_iocs;
use crate::store::Store;
use crate::text::to_plain;

const DAY: i64 = 86_400;
pub const MAX_IOCS: usize = 8_000;
pub const MAX_HITS: usize = 200;
pub const MAX_LINE: u64 = 64 * 1024;
pub const MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_SECONDS: u64 = 120;

#[derive(Clone, Debug)]
pub struct Ioc {
    pub kind: &'static str,
    pub story_id: String,
    pub story_title: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Hit {
    pub ioc: String,
    pub kind: &'static str,
    pub count: u64,
    pub first_line: u64,
    pub sample: String,
    pub story_id: String,
    pub story_title: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct HuntResult {
    pub file: String,
    pub lines: u64,
    pub bytes: u64,
    pub checked: usize,
    pub truncated: bool,
    pub hits: Vec<Hit>,
}

/// Indicators named in the last 30 days of stories, lower-cased, first story wins.
pub fn collect(store: &Store, now: i64) -> HashMap<String, Ioc> {
    let mut map: HashMap<String, Ioc> = HashMap::new();
    for s in store.stories_since(now - 30 * DAY).unwrap_or_default() {
        let text = format!(
            "{} {} {}",
            s.title,
            s.summary,
            store.article(&s.id).unwrap_or_default()
        );
        let i = extract_iocs(&text);
        let groups: [(&'static str, &Vec<String>); 4] = [
            ("ip", &i.ips),
            ("domain", &i.domains),
            ("sha256", &i.sha256),
            ("md5", &i.md5),
        ];
        for (kind, vals) in groups {
            for v in vals {
                if map.len() >= MAX_IOCS {
                    return map;
                }
                map.entry(v.to_lowercase()).or_insert_with(|| Ioc {
                    kind,
                    story_id: s.id.clone(),
                    story_title: to_plain(&s.title, 120),
                });
            }
        }
    }
    map
}

fn clean_sample(line: &str) -> String {
    let t: String = line.chars().filter(|c| !c.is_control()).take(220).collect();
    t.trim().to_string()
}

/// Scan a reader line by line. Returns (lines, bytes, truncated, hits).
pub fn scan<R: Read>(
    reader: R,
    iocs: &HashMap<String, Ioc>,
    max_bytes: u64,
    max_time: Duration,
) -> (u64, u64, bool, Vec<Hit>) {
    let started = Instant::now();
    let mut r = BufReader::with_capacity(1 << 20, reader);
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let (mut lines, mut bytes) = (0u64, 0u64);
    let mut truncated = false;
    let mut hits: HashMap<String, Hit> = HashMap::new();
    loop {
        buf.clear();
        let n = match (&mut r).take(MAX_LINE).read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        bytes += n as u64;
        lines += 1;
        if bytes > max_bytes || (lines % 4096 == 0 && started.elapsed() > max_time) {
            truncated = true;
            break;
        }
        let line = String::from_utf8_lossy(&buf);
        let mut seen_here: Vec<String> = Vec::new();
        for tok in line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')) {
            let tok = tok.trim_matches(|c| c == '.' || c == '-');
            if tok.len() < 4 || tok.len() > 80 {
                continue;
            }
            let key = if tok.bytes().any(|b| b.is_ascii_uppercase()) {
                tok.to_ascii_lowercase()
            } else {
                tok.to_string()
            };
            let mut candidates: Vec<&str> = vec![key.as_str()];
            // A match on a parent domain counts for its subdomains too.
            if key.contains('.') {
                let mut rest = key.as_str();
                while let Some(i) = rest.find('.') {
                    rest = &rest[i + 1..];
                    if rest.contains('.') {
                        candidates.push(rest);
                    }
                }
            }
            for c in candidates {
                if let Some(info) = iocs.get(c) {
                    if seen_here.iter().any(|s| s == c) {
                        continue;
                    }
                    seen_here.push(c.to_string());
                    if !hits.contains_key(c) && hits.len() >= MAX_HITS {
                        continue;
                    }
                    let e = hits.entry(c.to_string()).or_insert_with(|| Hit {
                        ioc: c.to_string(),
                        kind: info.kind,
                        count: 0,
                        first_line: lines,
                        sample: clean_sample(&line),
                        story_id: info.story_id.clone(),
                        story_title: info.story_title.clone(),
                    });
                    e.count += 1;
                }
            }
        }
    }
    let mut v: Vec<Hit> = hits.into_values().collect();
    v.sort_by_key(|h| (std::cmp::Reverse(h.count), h.first_line));
    (lines, bytes, truncated, v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> HashMap<String, Ioc> {
        let mut m = HashMap::new();
        for (k, kind) in [
            ("203.0.113.9", "ip"),
            ("evil-c2.example", "domain"),
            ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
        ] {
            m.insert(
                k.to_string(),
                Ioc {
                    kind,
                    story_id: "a".repeat(24),
                    story_title: "T".into(),
                },
            );
        }
        m
    }

    #[test]
    fn finds_ip_domain_subdomain_hash_in_mixed_logs() {
        let log = "ok 10.0.0.1 fine\n\
            {\"dest_ip\":\"203.0.113.9\",\"dest_port\":443}\n\
            GET http:\\/\\/Cdn.EVIL-C2.example\\/x 200\n\
            hash=D41D8CD98F00B204E9800998ECF8427E done\n\
            src 203.0.113.9:8080 again\n";
        let (lines, _, trunc, hits) = scan(log.as_bytes(), &set(), 1 << 20, Duration::from_secs(5));
        assert_eq!(lines, 5);
        assert!(!trunc);
        let ip = hits.iter().find(|h| h.ioc == "203.0.113.9").unwrap();
        assert_eq!((ip.count, ip.first_line), (2, 2));
        assert!(hits.iter().any(|h| h.ioc == "evil-c2.example"));
        assert!(hits.iter().any(|h| h.kind == "md5"));
        assert_eq!(hits.len(), 3);
    }

    #[test]
    fn clean_logs_have_no_hits_and_no_partial_matches() {
        let log = "203.0.113.90 and 1203.0.113.9 and notevil-c2.example\n";
        let (_, _, _, hits) = scan(log.as_bytes(), &set(), 1 << 20, Duration::from_secs(5));
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn samples_are_sanitised_and_short() {
        let log = format!("\u{1b}[31m 203.0.113.9 {}\n", "x".repeat(1000));
        let (_, _, _, hits) = scan(log.as_bytes(), &set(), 1 << 20, Duration::from_secs(5));
        assert!(hits[0].sample.len() <= 220);
        assert!(!hits[0].sample.contains('\u{1b}'));
    }

    #[test]
    fn size_cap_stops_the_scan() {
        let log = "203.0.113.9\n".repeat(1000);
        let (lines, _, trunc, _) = scan(log.as_bytes(), &set(), 100, Duration::from_secs(5));
        assert!(trunc && lines < 20);
    }

    #[test]
    fn huge_single_line_does_not_blow_memory() {
        let log = "a".repeat(500_000);
        let (lines, bytes, _, _) = scan(log.as_bytes(), &set(), 1 << 30, Duration::from_secs(5));
        assert!(lines >= 7 && bytes == 500_000);
    }
}
