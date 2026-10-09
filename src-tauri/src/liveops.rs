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

pub use crate::countries::{Country, COUNTRIES};

pub fn country(id: &str) -> Option<&'static Country> {
    COUNTRIES.iter().find(|c| c.id == id)
}

fn is_word_edge(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back().unwrap_or(' ');
    let after = text[end..].chars().next().unwrap_or(' ');
    !before.is_alphanumeric() && !after.is_alphanumeric()
}

/// Find the first whole-word occurrence of `needle` and blank it out, so a
/// shorter name inside a longer one ("Guinea" in "Papua New Guinea") is not
/// counted twice.
fn take_word(text: &mut String, needle: &str) -> bool {
    let mut from = 0;
    while let Some(i) = text[from..].find(needle) {
        let s = from + i;
        let e = s + needle.len();
        if is_word_edge(text, s, e) {
            text.replace_range(s..e, &" ".repeat(e - s));
            return true;
        }
        from = e;
    }
    false
}

/// Countries named in a piece of text (names, common short forms and
/// demonyms such as "Chinese"). Longest names are matched first.
pub fn countries_in(text: &str) -> Vec<&'static Country> {
    let mut lower = format!(" {} ", text.to_lowercase());
    let mut cased = format!(" {text} ");
    let mut names: Vec<(&'static str, &'static Country)> = COUNTRIES
        .iter()
        .flat_map(|c| c.aliases.iter().map(move |a| (*a, c)))
        .collect();
    names.sort_by_key(|(a, _)| std::cmp::Reverse(a.len()));
    let mut found: Vec<&'static Country> = Vec::new();
    for (alias, c) in names {
        if found.iter().any(|f| f.id == c.id) {
            continue;
        }
        let hit = if c.ambiguous {
            // Chad, Jordan, Georgia: only the capitalised form counts.
            let cap = format!("{}{}", alias[..1].to_uppercase(), &alias[1..]);
            take_word(&mut cased, &cap)
        } else {
            take_word(&mut lower, alias)
        };
        if hit {
            found.push(c);
        }
    }
    found.sort_by_key(|c| c.id);
    found
}

#[derive(Serialize, Debug, Clone)]
pub struct MapNode {
    pub id: &'static str,
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
            let n = nodes.entry(c.id).or_insert_with(|| MapNode {
                id: c.id,
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
                for c in cs.iter().filter(|c| c.id != origin.id) {
                    *arcs.entry((a.name, origin.id, c.id)).or_default() += 1;
                }
                // The origin country is always on the map when its actor is named.
                nodes.entry(origin.id).or_insert_with(|| MapNode {
                    id: origin.id,
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

/// Day keys (YYYY-MM-DD) read in the last 16 weeks, oldest first.
pub fn read_calendar(store: &Store, now: i64) -> Vec<String> {
    let today = Local.timestamp_opt(now, 0).single().map(|d| d.date_naive());
    let Some(today) = today else { return vec![] };
    let from = today - Duration::days(111);
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
    pub sources: usize,
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
        let ids: Vec<_> = c.iter().map(|c| c.id).collect();
        for want in [
            "United States of America",
            "United Kingdom",
            "China",
            "Hong Kong",
            "Turkey",
        ] {
            assert!(ids.contains(&want), "{want} in {ids:?}");
        }
        assert!(
            countries_in("Ukraine and Iranian drones; a skuk of mexicans")
                .iter()
                .all(|c| c.id != "United Kingdom")
        );
        assert!(countries_in("indiana jones").is_empty());
    }

    #[test]
    fn demonyms_and_long_names_win() {
        let ids = |t: &str| countries_in(t).iter().map(|c| c.id).collect::<Vec<_>>();
        assert_eq!(ids("Chinese and Russian hackers"), vec!["China", "Russia"]);
        // "Guinea" inside a longer name must not add Guinea
        let p = ids("A breach in Papua New Guinea");
        assert_eq!(p, vec!["Papua New Guinea"]);
        assert!(
            ids("Niger and Nigeria").contains(&"Niger")
                && ids("Niger and Nigeria").contains(&"Nigeria")
        );
        assert_eq!(
            ids("flaw in the Democratic Republic of the Congo"),
            vec!["Dem. Rep. Congo"]
        );
    }

    #[test]
    fn ambiguous_names_need_capitals() {
        let ids = |t: &str| countries_in(t).iter().map(|c| c.id).collect::<Vec<_>>();
        assert!(ids("attack in Chad last week").contains(&"Chad"));
        assert!(ids("the chad meme").is_empty());
        assert!(ids("Jordan said").contains(&"Jordan"));
    }

    #[test]
    fn country_table_covers_the_world() {
        let mut seen = std::collections::HashSet::new();
        for c in COUNTRIES {
            assert!(seen.insert(c.id), "dup {}", c.id);
            assert!((-90.0..=90.0).contains(&c.lat) && (-180.0..=180.0).contains(&c.lon));
            assert!(!c.aliases.is_empty());
        }
        assert!(COUNTRIES.len() > 200);
        for must in [
            "Brazil",
            "India",
            "Nigeria",
            "Australia",
            "Japan",
            "Egypt",
            "Singapore",
            "Argentina",
            "Kenya",
            "Canada",
        ] {
            assert!(country(must).is_some(), "{must}");
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
            .any(|a| a.actor == "APT28" && a.from == "Russia" && a.to == "Poland"));
        assert!(m.arcs.iter().all(|a| a.to != "Russia"));
        assert!(m.nodes.iter().any(|n| n.id == "Russia"));
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
