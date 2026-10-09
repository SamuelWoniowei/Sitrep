//! Data for the Live Ops page: the globe, CVE lifecycle tracker and the
//! reading calendar. All built from local data. The globe shows which
//! countries and groups are *named in recent news*; it is not a live feed of
//! attacks and does not claim to be.

use std::collections::BTreeMap;

use chrono::{Duration, Local, TimeZone};
use serde::Serialize;

use crate::intel::{actors_in, ACTORS};
use crate::store::Store;
use crate::text::to_plain;

pub struct Country {
    pub iso: &'static str,
    pub name: &'static str,
    pub lat: f64,
    pub lon: f64,
    pub aliases: &'static [&'static str],
}

macro_rules! c {
    ($iso:expr, $name:expr, $lat:expr, $lon:expr, [$($a:expr),*]) => {
        Country { iso: $iso, name: $name, lat: $lat, lon: $lon, aliases: &[$($a),*] }
    };
}

pub const COUNTRIES: &[Country] = &[
    c!(
        "US",
        "United States",
        39.8,
        -98.6,
        ["united states", "u.s.", "usa", "america"]
    ),
    c!(
        "GB",
        "United Kingdom",
        54.0,
        -2.0,
        [
            "united kingdom",
            "uk",
            "britain",
            "england",
            "scotland",
            "wales"
        ]
    ),
    c!(
        "RU",
        "Russia",
        61.5,
        105.0,
        ["russia", "russian federation"]
    ),
    c!("CN", "China", 35.0, 103.0, ["china"]),
    c!("KP", "North Korea", 40.0, 127.0, ["north korea", "dprk"]),
    c!("KR", "South Korea", 36.5, 127.8, ["south korea"]),
    c!("IR", "Iran", 32.4, 53.7, ["iran"]),
    c!("IL", "Israel", 31.0, 34.9, ["israel"]),
    c!("UA", "Ukraine", 48.4, 31.2, ["ukraine"]),
    c!("PL", "Poland", 52.0, 19.0, ["poland"]),
    c!("DE", "Germany", 51.0, 10.5, ["germany"]),
    c!("FR", "France", 46.6, 2.2, ["france"]),
    c!("IT", "Italy", 42.8, 12.8, ["italy"]),
    c!("ES", "Spain", 40.2, -3.7, ["spain"]),
    c!("NL", "Netherlands", 52.2, 5.3, ["netherlands", "dutch"]),
    c!("BE", "Belgium", 50.6, 4.7, ["belgium"]),
    c!("SE", "Sweden", 62.0, 15.0, ["sweden"]),
    c!("NO", "Norway", 61.0, 8.5, ["norway"]),
    c!("FI", "Finland", 64.0, 26.0, ["finland"]),
    c!("DK", "Denmark", 56.0, 10.0, ["denmark"]),
    c!("IE", "Ireland", 53.2, -8.0, ["ireland"]),
    c!("CH", "Switzerland", 46.8, 8.2, ["switzerland"]),
    c!("AT", "Austria", 47.6, 14.1, ["austria"]),
    c!("CZ", "Czechia", 49.8, 15.5, ["czech republic", "czechia"]),
    c!("RO", "Romania", 45.9, 25.0, ["romania"]),
    c!("GR", "Greece", 39.0, 22.0, ["greece"]),
    c!("PT", "Portugal", 39.5, -8.0, ["portugal"]),
    c!("HU", "Hungary", 47.2, 19.5, ["hungary"]),
    c!("BY", "Belarus", 53.7, 28.0, ["belarus"]),
    c!("TR", "Turkey", 39.0, 35.0, ["turkey", "türkiye"]),
    c!("IN", "India", 21.0, 78.0, ["india"]),
    c!("PK", "Pakistan", 30.0, 70.0, ["pakistan"]),
    c!("JP", "Japan", 36.0, 138.0, ["japan"]),
    c!("TW", "Taiwan", 23.7, 121.0, ["taiwan"]),
    c!("SG", "Singapore", 1.35, 103.8, ["singapore"]),
    c!("HK", "Hong Kong", 22.3, 114.2, ["hong kong"]),
    c!("AU", "Australia", -25.0, 134.0, ["australia"]),
    c!("NZ", "New Zealand", -41.0, 174.0, ["new zealand"]),
    c!("CA", "Canada", 56.0, -106.0, ["canada"]),
    c!("MX", "Mexico", 23.6, -102.5, ["mexico"]),
    c!("BR", "Brazil", -10.0, -52.0, ["brazil"]),
    c!("AR", "Argentina", -34.0, -64.0, ["argentina"]),
    c!("CO", "Colombia", 4.6, -74.1, ["colombia"]),
    c!("NG", "Nigeria", 9.1, 8.7, ["nigeria"]),
    c!("ZA", "South Africa", -29.0, 24.0, ["south africa"]),
    c!("EG", "Egypt", 26.8, 30.8, ["egypt"]),
    c!("KE", "Kenya", 0.0, 37.9, ["kenya"]),
    c!("SA", "Saudi Arabia", 24.0, 45.0, ["saudi arabia"]),
    c!(
        "AE",
        "United Arab Emirates",
        24.0,
        54.0,
        ["united arab emirates", "uae"]
    ),
    c!("QA", "Qatar", 25.3, 51.2, ["qatar"]),
    c!("IQ", "Iraq", 33.0, 44.0, ["iraq"]),
    c!("SY", "Syria", 35.0, 38.0, ["syria"]),
    c!("LB", "Lebanon", 33.9, 35.9, ["lebanon"]),
    c!("VN", "Vietnam", 16.0, 107.8, ["vietnam"]),
    c!("TH", "Thailand", 15.0, 101.0, ["thailand"]),
    c!("ID", "Indonesia", -2.5, 118.0, ["indonesia"]),
    c!("PH", "Philippines", 12.9, 122.0, ["philippines"]),
    c!("MY", "Malaysia", 4.2, 102.0, ["malaysia"]),
    c!("KZ", "Kazakhstan", 48.0, 67.0, ["kazakhstan"]),
];

pub fn country(iso: &str) -> Option<&'static Country> {
    COUNTRIES.iter().find(|c| c.iso == iso)
}

fn contains_word(hay: &str, needle: &str) -> bool {
    let mut start = 0;
    while let Some(i) = hay[start..].find(needle) {
        let s = start + i;
        let e = s + needle.len();
        let before = hay[..s].chars().next_back().unwrap_or(' ');
        let after = hay[e..].chars().next().unwrap_or(' ');
        // "u.s." ends in punctuation, so only check word edges that are letters.
        if !before.is_alphanumeric() && !after.is_alphanumeric() {
            return true;
        }
        start = e;
    }
    false
}

pub fn countries_in(text: &str) -> Vec<&'static Country> {
    let t = format!(" {} ", text.to_lowercase());
    COUNTRIES
        .iter()
        .filter(|c| c.aliases.iter().any(|a| contains_word(&t, a)))
        .collect()
}

#[derive(Serialize, Debug, Clone)]
pub struct MapNode {
    pub iso: &'static str,
    pub name: &'static str,
    pub lat: f64,
    pub lon: f64,
    pub count: usize,
    pub stories: Vec<(String, String)>,
}

#[derive(Serialize, Debug, Clone)]
pub struct MapArc {
    pub actor: &'static str,
    pub from: &'static str,
    pub to: &'static str,
    pub count: usize,
}

#[derive(Serialize, Debug, Clone)]
pub struct Edge {
    pub actor: &'static str,
    pub cve: String,
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct MapData {
    pub nodes: Vec<MapNode>,
    pub arcs: Vec<MapArc>,
    pub edges: Vec<Edge>,
    pub stories_considered: usize,
}

pub fn build_map(store: &Store, since: i64) -> MapData {
    let mut nodes: BTreeMap<&'static str, MapNode> = BTreeMap::new();
    let mut arcs: BTreeMap<(&'static str, &'static str, &'static str), usize> = BTreeMap::new();
    let mut edges: Vec<Edge> = Vec::new();
    let stories = store.stories_since(since).unwrap_or_default();
    for s in &stories {
        let text = format!("{} {}", s.title, s.summary);
        let cs = countries_in(&text);
        for c in &cs {
            let n = nodes.entry(c.iso).or_insert_with(|| MapNode {
                iso: c.iso,
                name: c.name,
                lat: c.lat,
                lon: c.lon,
                count: 0,
                stories: vec![],
            });
            n.count += 1;
            if n.stories.len() < 4 {
                n.stories.push((s.id.clone(), to_plain(&s.title, 110)));
            }
        }
        for a in actors_in(&text) {
            for cve in s.cves.iter().take(3) {
                let e = Edge {
                    actor: a.name,
                    cve: cve.clone(),
                };
                if edges.len() < 40 && !edges.iter().any(|x| x.actor == e.actor && x.cve == e.cve) {
                    edges.push(e);
                }
            }
            if a.country.is_empty() {
                continue;
            }
            if let Some(origin) = ACTORS
                .iter()
                .find(|x| x.name == a.name)
                .and_then(|x| country(x.country))
            {
                for c in cs.iter().filter(|c| c.iso != origin.iso) {
                    *arcs.entry((a.name, origin.iso, c.iso)).or_default() += 1;
                }
                // The origin country is always on the map when its actor is named.
                nodes.entry(origin.iso).or_insert_with(|| MapNode {
                    iso: origin.iso,
                    name: origin.name,
                    lat: origin.lat,
                    lon: origin.lon,
                    count: 0,
                    stories: vec![],
                });
            }
        }
    }
    let mut nodes: Vec<MapNode> = nodes.into_values().collect();
    nodes.sort_by_key(|n| std::cmp::Reverse(n.count));
    let mut arcs: Vec<MapArc> = arcs
        .into_iter()
        .map(|((actor, from, to), count)| MapArc {
            actor,
            from,
            to,
            count,
        })
        .collect();
    arcs.sort_by_key(|a| std::cmp::Reverse(a.count));
    arcs.truncate(24);
    MapData {
        nodes,
        arcs,
        edges,
        stories_considered: stories.len(),
    }
}

// ---------------- CVE lifecycle ----------------

#[derive(Serialize, Debug, Clone)]
pub struct CveTrack {
    pub cve: String,
    pub first_seen: i64,
    pub exploited_on: Option<String>,
    pub ransomware: bool,
    pub score: Option<f64>,
    pub severity: Option<String>,
    pub fix_mentioned: bool,
    pub stories: usize,
    pub headline: String,
}

pub fn cve_tracker(store: &Store, now: i64) -> Vec<CveTrack> {
    let mut map: BTreeMap<String, CveTrack> = BTreeMap::new();
    for s in store.stories_since(now - 14 * 86_400).unwrap_or_default() {
        let text = format!("{} {}", s.title, s.summary).to_lowercase();
        let fix = ["patch", "update", "fixed", "fix ", "hotfix", "mitigation"]
            .iter()
            .any(|w| text.contains(w));
        for cve in s.cves.iter().take(4) {
            let e = map.entry(cve.clone()).or_insert_with(|| CveTrack {
                cve: cve.clone(),
                first_seen: s.published,
                exploited_on: None,
                ransomware: false,
                score: None,
                severity: None,
                fix_mentioned: false,
                stories: 0,
                headline: to_plain(&s.title, 100),
            });
            e.stories += 1;
            e.first_seen = e.first_seen.min(s.published);
            e.fix_mentioned |= fix;
        }
    }
    for t in map.values_mut() {
        if let Some((score, sev)) = store.cvss(&t.cve) {
            t.score = Some(score);
            t.severity = Some(sev);
        }
        if let Ok(Some((added, ransom))) = store.kev_info(&t.cve) {
            t.exploited_on = Some(added);
            t.ransomware = ransom;
        }
    }
    let mut v: Vec<CveTrack> = map.into_values().collect();
    // Exploited first, then most covered.
    v.sort_by(|a, b| {
        b.exploited_on
            .is_some()
            .cmp(&a.exploited_on.is_some())
            .then(b.stories.cmp(&a.stories))
            .then(b.first_seen.cmp(&a.first_seen))
    });
    v.truncate(8);
    v
}

// ---------------- reading calendar ----------------

/// Day keys (YYYY-MM-DD) read in the last 12 weeks, oldest first.
pub fn read_calendar(store: &Store, now: i64) -> Vec<String> {
    let today = Local.timestamp_opt(now, 0).single().map(|d| d.date_naive());
    let Some(today) = today else { return vec![] };
    let from = today - Duration::days(83);
    let mut v: Vec<String> = store
        .read_days()
        .unwrap_or_default()
        .into_iter()
        .filter(|d| {
            chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d")
                .map(|x| x >= from && x <= today)
                .unwrap_or(false)
        })
        .collect();
    v.sort();
    v
}

#[derive(Serialize, Debug, Clone)]
pub struct LiveOps {
    pub map: MapData,
    pub cves: Vec<CveTrack>,
    pub calendar: Vec<String>,
    pub today: String,
    pub streak: i64,
    pub exploited_14d: i64,
    pub new_today: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::RawItem;

    #[test]
    fn countries_matched_as_words() {
        let c = countries_in(
            "The UK and the U.S. warned that China-linked hackers hit Hong Kong and Turkey",
        );
        let isos: Vec<_> = c.iter().map(|c| c.iso).collect();
        for want in ["US", "GB", "CN", "HK", "TR"] {
            assert!(isos.contains(&want), "{want} in {isos:?}");
        }
        assert!(
            countries_in("Ukraine and Iranian drones; a skuk of mexicans")
                .iter()
                .all(|c| c.iso != "GB")
        );
        assert!(countries_in("indiana jones").is_empty());
    }

    #[test]
    fn country_table_is_sane() {
        let mut seen = std::collections::HashSet::new();
        for c in COUNTRIES {
            assert!(seen.insert(c.iso), "dup {}", c.iso);
            assert!((-90.0..=90.0).contains(&c.lat) && (-180.0..=180.0).contains(&c.lon));
        }
        for a in ACTORS.iter().filter(|a| !a.country.is_empty()) {
            assert!(country(a.country).is_some(), "{}", a.name);
        }
    }

    #[test]
    fn map_links_actor_origin_to_named_countries() {
        let st = Store::open_in_memory().unwrap();
        let now = 1_791_500_000;
        st.upsert_items(
            &[RawItem {
                title: "APT28 targets Poland and Germany with CVE-2026-0042".into(),
                link: Some("https://example.org/a".into()),
                summary: "Fancy Bear phishing campaign".into(),
                published: now - 100,
                source_id: "s".into(),
                source_name: "S".into(),
                cves: vec!["CVE-2026-0042".into()],
            }],
            now,
        )
        .unwrap();
        let m = build_map(&st, now - 86_400);
        assert!(m
            .arcs
            .iter()
            .any(|a| a.actor == "APT28" && a.from == "RU" && a.to == "PL"));
        assert!(m.arcs.iter().all(|a| a.to != "RU"));
        assert!(m.nodes.iter().any(|n| n.iso == "RU"));
        assert_eq!(m.edges.len(), 1);
    }

    #[test]
    fn calendar_only_has_recent_days() {
        let st = Store::open_in_memory().unwrap();
        let now = 1_791_500_000;
        let today = crate::core::day_key(now);
        st.mark_read(&today, "aaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap_or_default();
        st.mark_read("2020-01-01", "bbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap_or_default();
        let c = read_calendar(&st, now);
        assert!(c.contains(&today) && !c.contains(&"2020-01-01".to_string()));
    }
}
