//! Intelligence features built from stored data: smart glossary, developing
//! stories, threat-actor profiles, "Am I affected?" and the Lab pack.
//! Everything here is pure logic over the local database plus one read-only
//! look at the installed-programs list. No network.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use regex::Regex;
use serde::Serialize;

use crate::ai::AiTerm;
use crate::glossary::TERMS;
use crate::store::{KevRow, Store, StoryRow};
use crate::text::{jaccard, title_tokens, to_plain};

const DAY: i64 = 86_400;
pub const AI_TERM_CAP: i64 = 15;

// ======================= smart glossary =======================

/// Normal form used to merge duplicates: lower-case letters and digits only,
/// no bracketed part, and a trailing plural "s" removed.
pub fn canon(term: &str) -> String {
    let base = term.split('(').next().unwrap_or(term);
    let mut k: String = base
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect();
    if k.len() > 3 && k.ends_with('s') && !k.ends_with("ss") {
        k.pop();
    }
    k
}

fn builtin_keys() -> HashSet<String> {
    let mut set = HashSet::new();
    for t in TERMS {
        set.insert(canon(t.term));
        if let (Some(a), Some(b)) = (t.term.find('('), t.term.find(')')) {
            if a < b {
                set.insert(canon(&t.term[a + 1..b]));
            }
        }
    }
    set
}

/// Remember jargon the AI explained, unless it is a duplicate or the cap of
/// active AI-added terms is reached.
pub fn add_ai_terms(store: &Store, terms: &[AiTerm], now: i64) {
    let builtin = builtin_keys();
    for t in terms {
        let key = canon(&t.term);
        if key.len() < 2 || builtin.contains(&key) || store.gloss_has(&key) {
            continue;
        }
        if store.gloss_ai_active() >= AI_TERM_CAP {
            break;
        }
        let _ = store.gloss_insert(
            &key,
            &to_plain(&t.term, 40),
            &to_plain(&t.plain, 240),
            "",
            "ai",
            now,
        );
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct GlossEntry {
    pub key: String,
    pub term: String,
    pub plain: String,
    pub analogy: String,
    pub status: String,
    pub origin: String,
}

pub fn glossary_view(store: &Store) -> Vec<GlossEntry> {
    let rows = store.gloss_rows().unwrap_or_default();
    let mut out: Vec<GlossEntry> = TERMS
        .iter()
        .map(|t| {
            let key = canon(t.term);
            let status = rows
                .iter()
                .find(|r| r.key == key)
                .map(|r| r.status.clone())
                .unwrap_or_else(|| "new".into());
            GlossEntry {
                key,
                term: t.term.into(),
                plain: t.plain.into(),
                analogy: t.analogy.into(),
                status,
                origin: "builtin".into(),
            }
        })
        .collect();
    let builtin = builtin_keys();
    for r in rows
        .into_iter()
        .filter(|r| r.origin == "ai" && !r.archived && !builtin.contains(&r.key))
    {
        out.push(GlossEntry {
            key: r.key,
            term: r.term,
            plain: r.plain,
            analogy: r.analogy,
            status: r.status,
            origin: "ai".into(),
        });
    }
    out.sort_by_key(|e| e.term.to_lowercase());
    out
}

pub fn set_gloss_status(store: &Store, key: &str, status: &str, now: i64) -> Result<(), String> {
    if !matches!(status, "new" | "learning" | "known") {
        return Err("invalid status".into());
    }
    if let Some(t) = TERMS.iter().find(|t| canon(t.term) == key) {
        return store
            .gloss_set_status(key, t.term, t.plain, t.analogy, status, now)
            .map_err(|e| e.to_string());
    }
    if store.gloss_has(key) {
        let r = store
            .gloss_rows()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|r| r.key == key)
            .ok_or("unknown term")?;
        return store
            .gloss_set_status(key, &r.term, &r.plain, &r.analogy, status, now)
            .map_err(|e| e.to_string());
    }
    Err("unknown term".into())
}

// ======================= developing stories =======================

#[derive(Serialize, Clone, Debug)]
pub struct TimelineItem {
    pub id: String,
    pub title: String,
    pub source: String,
    pub published: i64,
    pub why: &'static str,
}

/// Earlier or later stories about the same thing: they share a CVE, or their
/// headlines are quite similar (but not so similar they were merged already).
pub fn developing(store: &Store, story: &StoryRow) -> Vec<TimelineItem> {
    let tokens = title_tokens(&story.title);
    let mut out: Vec<TimelineItem> = store
        .stories_since(story.published - 14 * DAY)
        .unwrap_or_default()
        .into_iter()
        .filter(|o| o.id != story.id && o.published <= story.published + 14 * DAY)
        .filter_map(|o| {
            let shared_cve = o.cves.iter().any(|c| story.cves.contains(c));
            let similar = jaccard(&tokens, &title_tokens(&o.title)) >= 0.35;
            if shared_cve || similar {
                Some(TimelineItem {
                    id: o.id,
                    title: to_plain(&o.title, 140),
                    source: o.sources.first().cloned().unwrap_or_default(),
                    published: o.published,
                    why: if shared_cve {
                        "same CVE"
                    } else {
                        "similar story"
                    },
                })
            } else {
                None
            }
        })
        .collect();
    out.sort_by_key(|t| t.published);
    out.truncate(8);
    out
}

#[derive(Serialize, Clone, Debug)]
pub struct ClusterItem {
    pub id: String,
    pub title: String,
    pub source: String,
    pub published: i64,
    pub day: i64, // 1 = first story in the cluster
    pub read: bool,
    pub new: bool, // unread and newer than something you already read
}

#[derive(Serialize, Clone, Debug)]
pub struct Cluster {
    pub title: String,
    pub first: i64,
    pub last: i64,
    pub days: i64,
    pub cves: Vec<String>,
    pub new_count: usize,
    pub items: Vec<ClusterItem>,
}

/// Group stories from `since` onward into developing stories: two stories join
/// when they share a CVE or have similar titles. Only groups of 2+ are kept.
pub fn clusters(store: &Store, read: &HashSet<String>, since: i64) -> Vec<Cluster> {
    let stories = store.stories_since(since).unwrap_or_default();
    let n = stories.len().min(600);
    let stories = &stories[..n];
    let toks: Vec<Vec<String>> = stories.iter().map(|s| title_tokens(&s.title)).collect();
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(p: &mut [usize], mut x: usize) -> usize {
        while p[x] != x {
            p[x] = p[p[x]];
            x = p[x];
        }
        x
    }
    for i in 0..n {
        for j in (i + 1)..n {
            let cve = stories[i].cves.iter().any(|c| stories[j].cves.contains(c));
            if cve
                || ((stories[i].published - stories[j].published).abs() <= 14 * DAY
                    && jaccard(&toks[i], &toks[j]) >= 0.35)
            {
                let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                if a != b {
                    parent[a] = b;
                }
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..n {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(i);
    }
    let mut out: Vec<Cluster> = Vec::new();
    for (_, mut idx) in groups {
        if idx.len() < 2 {
            continue;
        }
        idx.sort_by_key(|&i| stories[i].published);
        let first = stories[idx[0]].published;
        let mut seen_read_at: Option<i64> = None;
        let mut items = Vec::new();
        for &i in idx.iter().take(10) {
            let s = &stories[i];
            let is_read = read.contains(&s.id);
            let new = !is_read && seen_read_at.is_some_and(|t| s.published >= t);
            if is_read && seen_read_at.is_none() {
                seen_read_at = Some(s.published);
            }
            items.push(ClusterItem {
                id: s.id.clone(),
                title: to_plain(&s.title, 140),
                source: s.sources.first().cloned().unwrap_or_default(),
                published: s.published,
                day: (s.published - first) / DAY + 1,
                read: is_read,
                new,
            });
        }
        let mut cves: Vec<String> = idx.iter().flat_map(|&i| stories[i].cves.clone()).collect();
        cves.sort();
        cves.dedup();
        cves.truncate(4);
        let last = stories[*idx.last().unwrap()].published;
        out.push(Cluster {
            title: to_plain(&stories[*idx.last().unwrap()].title, 140),
            first,
            last,
            days: (last - first) / DAY + 1,
            cves,
            new_count: items.iter().filter(|i| i.new).count(),
            items,
        });
    }
    out.sort_by_key(|c| std::cmp::Reverse(c.last));
    out.truncate(12);
    out
}

// ======================= watchlist board =======================

#[derive(Serialize, Clone, Debug)]
pub struct WatchRow {
    pub term: String,
    pub total: usize,
    pub per_day: Vec<u32>, // last 14 days, oldest first
    pub latest: Vec<(String, String, i64)>, // id, headline, published
}

pub fn watch_board(store: &Store, terms: &[String], now: i64) -> Vec<WatchRow> {
    let stories = store.stories_since(now - 30 * DAY).unwrap_or_default();
    terms
        .iter()
        .map(|term| {
            let needle = term.to_lowercase();
            let mut per_day = vec![0u32; 14];
            let mut hits: Vec<&StoryRow> = Vec::new();
            for s in &stories {
                if format!("{} {}", s.title, s.summary).to_lowercase().contains(&needle) {
                    hits.push(s);
                    let age = (now - s.published) / DAY;
                    if (0..14).contains(&age) {
                        per_day[(13 - age) as usize] += 1;
                    }
                }
            }
            WatchRow {
                term: term.clone(),
                total: hits.len(),
                per_day,
                latest: hits
                    .iter()
                    .take(4)
                    .map(|s| (s.id.clone(), to_plain(&s.title, 120), s.published))
                    .collect(),
            }
        })
        .collect()
}

#[derive(Serialize, Clone, Debug)]
pub struct WeekStory {
    pub id: String,
    pub headline: String,
    pub published: i64,
    pub cves: Vec<String>,
    pub iocs: usize,
}

/// Last 7 days of stories that carry CVEs or indicators: candidates for the lab pack.
pub fn week_stories(store: &Store, now: i64) -> Vec<WeekStory> {
    let mut v: Vec<WeekStory> = store
        .stories_since(now - 7 * DAY)
        .unwrap_or_default()
        .into_iter()
        .map(|s| {
            let i = extract_iocs(&format!("{} {}", s.title, s.summary));
            WeekStory {
                headline: to_plain(&s.title, 140),
                published: s.published,
                iocs: i.ips.len() + i.domains.len() + i.sha256.len() + i.md5.len(),
                cves: s.cves.iter().take(4).cloned().collect(),
                id: s.id,
            }
        })
        .filter(|w| w.iocs > 0 || !w.cves.is_empty())
        .collect();
    v.sort_by_key(|w| std::cmp::Reverse((w.cves.len() + w.iocs.min(5), w.published)));
    v.truncate(24);
    v
}

// ======================= threat actors =======================

pub struct Actor {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub kind: &'static str,
    pub origin: &'static str,
    pub country: &'static str, // map country id, or "" if not pinned to one
    pub blurb: &'static str,
}

pub const ACTORS: &[Actor] = &[
    Actor { name: "APT28", aliases: &["apt28", "fancy bear", "forest blizzard", "sofacy", "strontium"], kind: "State-linked", origin: "Russia", country: "Russia", blurb: "Linked to Russian military intelligence (GRU). Known for phishing and credential theft against governments, militaries and elections." },
    Actor { name: "APT29", aliases: &["apt29", "cozy bear", "midnight blizzard", "nobelium"], kind: "State-linked", origin: "Russia", country: "Russia", blurb: "Linked to Russia's foreign intelligence service (SVR). Quiet, long-running espionage; behind the SolarWinds supply-chain compromise." },
    Actor { name: "Sandworm", aliases: &["sandworm", "seashell blizzard", "voodoo bear"], kind: "State-linked", origin: "Russia", country: "Russia", blurb: "Linked to Russian military intelligence (GRU). Destructive attacks, including on Ukraine's power grid and the NotPetya outbreak." },
    Actor { name: "Lazarus Group", aliases: &["lazarus", "hidden cobra", "diamond sleet"], kind: "State-linked", origin: "North Korea", country: "North Korea", blurb: "North Korean state-linked group best known for large cryptocurrency thefts and the Sony Pictures attack." },
    Actor { name: "Kimsuky", aliases: &["kimsuky", "emerald sleet", "velvet chollima"], kind: "State-linked", origin: "North Korea", country: "North Korea", blurb: "North Korean espionage group that targets think tanks, researchers and officials, usually through convincing phishing." },
    Actor { name: "Volt Typhoon", aliases: &["volt typhoon"], kind: "State-linked", origin: "China", country: "China", blurb: "Chinese state-linked group that hides inside critical-infrastructure networks using built-in tools, rather than malware, to stay unseen." },
    Actor { name: "Salt Typhoon", aliases: &["salt typhoon"], kind: "State-linked", origin: "China", country: "China", blurb: "Chinese state-linked group reported to have breached telecommunications providers to reach call and message data." },
    Actor { name: "APT41", aliases: &["apt41", "winnti", "brass typhoon"], kind: "State-linked", origin: "China", country: "China", blurb: "Chinese group that mixes government espionage with financially motivated crime." },
    Actor { name: "MuddyWater", aliases: &["muddywater", "mango sandstorm"], kind: "State-linked", origin: "Iran", country: "Iran", blurb: "Iranian state-linked group linked to the country's intelligence ministry; targets governments and telecoms, mainly in the Middle East." },
    Actor { name: "Charming Kitten", aliases: &["charming kitten", "apt35", "mint sandstorm", "phosphorus"], kind: "State-linked", origin: "Iran", country: "Iran", blurb: "Iranian state-linked group known for patient, personalised phishing aimed at journalists, activists and officials." },
    Actor { name: "Scattered Spider", aliases: &["scattered spider", "octo tempest", "unc3944"], kind: "Criminal", origin: "Mostly English-speaking, loosely US/UK", country: "", blurb: "Financially motivated crew that phones IT help desks and tricks staff into resetting access, then deploys ransomware." },
    Actor { name: "LockBit", aliases: &["lockbit"], kind: "Criminal", origin: "Russia-based operators reported", country: "", blurb: "Ransomware-as-a-service operation disrupted by law enforcement in 2024 but repeatedly seen trying to return." },
    Actor { name: "ALPHV / BlackCat", aliases: &["alphv", "blackcat"], kind: "Criminal", origin: "Unknown", country: "", blurb: "Ransomware-as-a-service group that was disrupted in late 2023 and later shut down." },
    Actor { name: "Cl0p", aliases: &["cl0p", "clop"], kind: "Criminal", origin: "Russia-linked reported", country: "", blurb: "Ransomware and extortion group known for mass data theft by exploiting file-transfer software such as MOVEit." },
];

pub fn actors_in(text: &str) -> Vec<&'static Actor> {
    let t = format!(" {} ", text.to_lowercase());
    ACTORS
        .iter()
        .filter(|a| {
            a.aliases.iter().any(|al| {
                // whole-word match so "clop" does not match "clopidogrel"
                let mut start = 0;
                while let Some(i) = t[start..].find(al) {
                    let s = start + i;
                    let e = s + al.len();
                    let before = t[..s].chars().next_back().unwrap_or(' ');
                    let after = t[e..].chars().next().unwrap_or(' ');
                    if !before.is_alphanumeric() && !after.is_alphanumeric() {
                        return true;
                    }
                    start = e;
                }
                false
            })
        })
        .collect()
}

#[derive(Serialize, Clone, Debug)]
pub struct ActorSeen {
    pub name: &'static str,
    pub kind: &'static str,
    pub origin: &'static str,
    pub country: &'static str,
    pub blurb: &'static str,
    pub wants: &'static str,
    pub how: &'static str,
    pub stories: Vec<(String, String)>, // (id, headline)
}

/// (what they want, how they usually operate): short, plain-English.
pub fn profile(name: &str) -> (&'static str, &'static str) {
    match name {
        "APT28" => ("Political and military intelligence, and influence over governments and elections.", "Spear-phishing, fake login pages and password guessing to steal credentials, then quiet access to email and networks."),
        "APT29" => ("Long-term foreign-policy and security intelligence.", "Stealthy access to cloud accounts and email, stolen sign-in tokens and supply-chain compromise. Avoids noisy malware."),
        "Sandworm" => ("Disruption and destruction, to pressure Ukraine and its allies.", "Breaks into IT and industrial networks, then uses wiper malware and power-grid attacks, sometimes disguised as ransomware."),
        "Lazarus Group" => ("Money for the North Korean state, plus some espionage.", "Fake job offers and trojanised software aimed at crypto and tech firms, then laundering the stolen funds."),
        "Kimsuky" => ("Intelligence on foreign policy, nuclear and sanctions matters.", "Tailored phishing posing as journalists or academics, then malicious documents and credential theft."),
        "Volt Typhoon" => ("Hidden, lasting access to critical infrastructure, reported as preparation for possible future disruption.", "Exploits internet-facing devices such as routers and VPNs, then uses built-in Windows tools to blend in with normal activity."),
        "Salt Typhoon" => ("Intelligence from telecom networks: who talks to whom, and some message content.", "Compromises network devices at telecom providers and stays hidden for long periods."),
        "APT41" => ("Espionage for the state and, separately, profit.", "Exploits flaws in internet-facing software and supply-chain access, with a wide malware toolkit."),
        "MuddyWater" => ("Intelligence on governments and telecoms, mainly in the Middle East.", "Phishing that installs remote-admin tools, then scripts and legitimate software to stay in."),
        "Charming Kitten" => ("Information about journalists, activists, academics and officials that Iran cares about.", "Long, friendly conversations and fake meeting links that end in credential theft."),
        "Scattered Spider" => ("Money, through data theft, extortion and ransomware.", "Phones IT help desks pretending to be staff to get passwords or MFA reset, then moves into cloud and virtual machines."),
        "LockBit" => ("Ransom payments.", "Affiliates get in through stolen logins or unpatched systems, steal data, encrypt files, then demand payment to unlock and not to leak."),
        "ALPHV / BlackCat" => ("Ransom payments.", "Affiliates rented the ransomware, stole data first, then threatened to publish it."),
        "Cl0p" => ("Mass extortion payments.", "Finds a flaw in widely used file-transfer software, steals data from many victims at once, then demands payment not to leak it."),
        _ => ("", ""),
    }
}

pub fn actors_seen(store: &Store, since: i64) -> Vec<ActorSeen> {
    let mut map: BTreeMap<&'static str, ActorSeen> = BTreeMap::new();
    for s in store.stories_since(since).unwrap_or_default() {
        for a in actors_in(&format!("{} {}", s.title, s.summary)) {
            map.entry(a.name)
                .or_insert_with(|| ActorSeen {
                    name: a.name,
                    kind: a.kind,
                    origin: a.origin,
                    country: a.country,
                    blurb: a.blurb,
                    wants: profile(a.name).0,
                    how: profile(a.name).1,
                    stories: vec![],
                })
                .stories
                .push((s.id.clone(), to_plain(&s.title, 120)));
        }
    }
    let mut v: Vec<ActorSeen> = map.into_values().collect();
    v.sort_by_key(|a| std::cmp::Reverse(a.stories.len()));
    v
}

// ======================= "Am I affected?" =======================

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Exposure {
    pub program: String,
    pub vendor: String,
    pub product: String,
    pub cves: Vec<String>,
    pub latest_added: String,
    pub ransomware: bool,
}

/// Parse `reg query ... /v DisplayName` output into program names.
pub fn parse_reg_output(out: &str) -> Vec<String> {
    let mut names = BTreeSet::new();
    for line in out.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("DisplayName") {
            if let Some(v) = rest.trim_start().strip_prefix("REG_SZ") {
                let name = to_plain(v.trim(), 120);
                if name.len() >= 3 {
                    names.insert(name);
                }
            }
        }
    }
    names.into_iter().collect()
}

fn words(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect()
}

const GENERIC: &[&str] = &[
    "the",
    "and",
    "for",
    "server",
    "windows",
    "microsoft",
    "software",
    "system",
    "systems",
    "client",
    "web",
    "mobile",
    "enterprise",
    "services",
    "service",
    "manager",
    "management",
    "platform",
    "suite",
    "pro",
    "edition",
    "version",
    "x64",
    "x86",
    "update",
    "runtime",
    "framework",
];

/// Does an installed program plausibly correspond to a KEV vendor + product?
pub fn program_matches(program: &str, vendor: &str, product: &str) -> bool {
    let pw: HashSet<String> = words(program).into_iter().collect();
    let prod: Vec<String> = words(product)
        .into_iter()
        .filter(|w| !GENERIC.contains(&w.as_str()))
        .collect();
    if prod.is_empty() || prod.iter().map(String::len).sum::<usize>() < 3 {
        return false;
    }
    if !prod.iter().all(|w| pw.contains(w)) {
        return false;
    }
    // Short product names (e.g. "7-Zip", "vpn") must be backed by the vendor name.
    let vend: Vec<String> = words(vendor)
        .into_iter()
        .filter(|w| w.len() >= 3 && !GENERIC.contains(&w.as_str()))
        .collect();
    prod.iter().map(String::len).sum::<usize>() >= 6 || vend.iter().any(|v| pw.contains(v))
}

/// Match installed programs against recently added KEV entries. This cannot
/// compare version numbers, so a match means "worth checking", not "broken".
pub fn exposure(programs: &[String], kev: &[KevRow]) -> Vec<Exposure> {
    let mut by_prog: BTreeMap<String, Exposure> = BTreeMap::new();
    for p in programs {
        for k in kev {
            if program_matches(p, &k.vendor, &k.product) {
                let e = by_prog.entry(p.clone()).or_insert_with(|| Exposure {
                    program: p.clone(),
                    vendor: k.vendor.clone(),
                    product: k.product.clone(),
                    cves: vec![],
                    latest_added: String::new(),
                    ransomware: false,
                });
                if !e.cves.contains(&k.cve) && e.cves.len() < 10 {
                    e.cves.push(k.cve.clone());
                }
                if k.date_added > e.latest_added {
                    e.latest_added = k.date_added.clone();
                }
                e.ransomware |= k.ransomware;
            }
        }
    }
    let mut v: Vec<Exposure> = by_prog.into_values().collect();
    v.sort_by(|a, b| b.latest_added.cmp(&a.latest_added));
    v
}

/// Read-only list of installed program names (Windows registry). Elsewhere
/// it returns nothing. Nothing is stored or sent anywhere.
pub async fn installed_programs() -> Vec<String> {
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let reg = format!(r"{root}\System32\reg.exe");
        let keys = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ];
        let mut all = String::new();
        for k in keys {
            let mut cmd = tokio::process::Command::new(&reg);
            cmd.args(["query", k, "/s", "/v", "DisplayName"])
                .creation_flags(0x0800_0000);
            if let Ok(Ok(o)) =
                tokio::time::timeout(std::time::Duration::from_secs(20), cmd.output()).await
            {
                all.push_str(&String::from_utf8_lossy(&o.stdout));
                all.push('\n');
            }
        }
        parse_reg_output(&all)
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

// ======================= Lab pack =======================

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct Iocs {
    pub ips: Vec<String>,
    pub domains: Vec<String>,
    pub sha256: Vec<String>,
    pub md5: Vec<String>,
}

const IOC_CAP: usize = 40;

const IGNORE_DOMAINS: &[&str] = &[
    "microsoft.com",
    "google.com",
    "github.com",
    "cisa.gov",
    "nist.gov",
    "mitre.org",
    "wikipedia.org",
    "bleepingcomputer.com",
    "therecord.media",
    "thehackernews.com",
    "ncsc.gov.uk",
    "sans.edu",
    "krebsonsecurity.com",
    "talosintelligence.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "youtube.com",
    "apple.com",
    "amazon.com",
    "cloudflare.com",
    "virustotal.com",
    "example.com",
];

const TLDS: &[&str] = &[
    "com", "net", "org", "io", "ru", "cn", "info", "biz", "xyz", "top", "online", "site", "cc",
    "co", "uk", "de", "fr", "nl", "ir", "kp", "su", "tk", "ml", "ga", "cf", "gq", "pw", "ws", "me",
    "tv", "app", "dev", "cloud", "shop", "club", "live", "icu", "vip", "work", "link", "click",
    "store", "tech", "pro", "in", "br", "ua", "pl", "tr", "kr", "jp", "hk", "sg", "to", "sh", "ly",
    "gg", "id", "us", "eu", "ch", "se",
];

fn refang(text: &str) -> String {
    text.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[dot]", ".")
        .replace("(dot)", ".")
        .replace("hxxp", "http")
}

fn public_ipv4(s: &str) -> bool {
    let o: Vec<u8> = match s
        .split('.')
        .map(|p| p.parse::<u8>())
        .collect::<Result<_, _>>()
    {
        Ok(v) => v,
        Err(_) => return false,
    };
    if o.len() != 4 || s.split('.').any(|p| p.len() > 1 && p.starts_with('0')) {
        return false;
    }
    !(o[0] == 0
        || o[0] == 10
        || o[0] == 127
        || o[0] >= 224
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 100 && (64..=127).contains(&o[1])))
}

pub fn extract_iocs(text: &str) -> Iocs {
    let t = refang(text);
    let ip_re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    let dom_re =
        Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b").unwrap();
    let h256 = Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap();
    let h32 = Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap();
    let mut out = Iocs::default();
    let push = |v: &mut Vec<String>, s: String| {
        if v.len() < IOC_CAP && !v.contains(&s) {
            v.push(s);
        }
    };
    for m in ip_re.find_iter(&t) {
        if public_ipv4(m.as_str()) {
            push(&mut out.ips, m.as_str().to_string());
        }
    }
    for m in dom_re.find_iter(&t) {
        let d = m.as_str().to_lowercase();
        let tld = d.rsplit('.').next().unwrap_or("");
        if !TLDS.contains(&tld) || d.len() > 80 {
            continue;
        }
        if IGNORE_DOMAINS
            .iter()
            .any(|g| d == *g || d.ends_with(&format!(".{g}")))
        {
            continue;
        }
        // Skip things that are really IPs/versions already handled.
        if d.split('.').all(|p| p.chars().all(|c| c.is_ascii_digit())) {
            continue;
        }
        push(&mut out.domains, d);
    }
    for m in h256.find_iter(&t) {
        push(&mut out.sha256, m.as_str().to_lowercase());
    }
    for m in h32.find_iter(&t) {
        // A 32-hex run inside a longer hash was already excluded by \b.
        push(&mut out.md5, m.as_str().to_lowercase());
    }
    out
}

fn valid_ioc_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 80
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Build the lab pack files as (filename, contents). Every value placed in a
/// rule has been through a strict character check first.
pub fn lab_pack_files(
    title: &str,
    link: Option<&str>,
    cves: &[String],
    iocs: &Iocs,
    date: &str,
) -> Vec<(String, String)> {
    let title = to_plain(title, 140);
    let mut csv = String::from("type,value\n");
    for v in &iocs.ips {
        csv.push_str(&format!("ip,{v}\n"));
    }
    for v in iocs.domains.iter().filter(|d| valid_ioc_domain(d)) {
        csv.push_str(&format!("domain,{v}\n"));
    }
    for v in &iocs.sha256 {
        csv.push_str(&format!("sha256,{v}\n"));
    }
    for v in &iocs.md5 {
        csv.push_str(&format!("md5,{v}\n"));
    }

    let mut suri = format!("# Sitrep DRAFT Suricata rules, generated {date}. LAB USE ONLY: test before trusting.\n# Story: {title}\n");
    let mut sid = 9_100_000;
    for ip in &iocs.ips {
        suri.push_str(&format!("alert ip $HOME_NET any -> {ip} any (msg:\"SITREP DRAFT IOC outbound to {ip}\"; classtype:trojan-activity; sid:{sid}; rev:1;)\n"));
        sid += 1;
    }
    for d in iocs.domains.iter().filter(|d| valid_ioc_domain(d)) {
        suri.push_str(&format!("alert dns $HOME_NET any -> any any (msg:\"SITREP DRAFT IOC DNS lookup {d}\"; dns.query; content:\"{d}\"; nocase; endswith; classtype:trojan-activity; sid:{sid}; rev:1;)\n"));
        sid += 1;
    }

    let mut ip_list = String::new();
    for ip in &iocs.ips {
        ip_list.push_str(&format!("{ip}:sitrep\n"));
    }
    let mut dom_list = String::new();
    for d in iocs.domains.iter().filter(|d| valid_ioc_domain(d)) {
        dom_list.push_str(&format!("{d}:sitrep\n"));
    }
    let mut hash_list = String::new();
    for h in iocs.sha256.iter().chain(iocs.md5.iter()) {
        hash_list.push_str(&format!("{h}:sitrep\n"));
    }

    let wazuh = format!(
        "<!-- Sitrep DRAFT Wazuh rules, generated {date}. LAB USE ONLY. -->\n\
<!-- Add to /var/ossec/etc/rules/local_rules.xml, add the three <list> lines from the README to ossec.conf, then restart the manager. -->\n\
<group name=\"sitrep,\">\n\
  <rule id=\"100500\" level=\"10\">\n    <if_group>web|firewall|syslog</if_group>\n    <list field=\"srcip\" lookup=\"address_match_key\">etc/lists/sitrep-ioc-ips</list>\n    <description>Sitrep DRAFT: traffic from an IP in a recent story's IOC list</description>\n  </rule>\n\
  <rule id=\"100501\" level=\"10\">\n    <if_group>syscheck</if_group>\n    <list field=\"sha256_after\" lookup=\"match_key\">etc/lists/sitrep-ioc-hashes</list>\n    <description>Sitrep DRAFT: file hash matches a recent story's IOC list</description>\n  </rule>\n\
</group>\n"
    );

    let cve_line = if cves.is_empty() {
        "none listed".to_string()
    } else {
        cves.join(", ")
    };
    let readme = format!(
        "# Sitrep lab pack\n\nGenerated {date} from the story: {title}\nSource: {}\nCVEs: {cve_line}\n\nIndicators found: {} IPs, {} domains, {} SHA-256 hashes, {} MD5 hashes.\n\n\
**These files are drafts, extracted automatically from a news article. Indicators can be wrong or out of date. Use them only in your lab, never to block things in production.**\n\n\
## Files\n- `iocs.csv`: everything found, one per line.\n- `suricata.rules`: draft alert rules (copy into your Suricata rules folder, run `suricata -T` to test, then reload).\n- `sitrep-ioc-ips`, `sitrep-ioc-domains`, `sitrep-ioc-hashes`: Wazuh CDB lists.\n- `wazuh_rules.xml`: draft Wazuh rules that use those lists.\n\n\
## Loading into Wazuh (in your VM)\n1. Copy the three list files to `/var/ossec/etc/lists/`.\n2. In `ossec.conf`, inside `<ruleset>`, add:\n   `<list>etc/lists/sitrep-ioc-ips</list>`\n   `<list>etc/lists/sitrep-ioc-domains</list>`\n   `<list>etc/lists/sitrep-ioc-hashes</list>`\n3. Paste `wazuh_rules.xml` into `/var/ossec/etc/rules/local_rules.xml`.\n4. Check with `/var/ossec/bin/wazuh-logtest`, then restart the manager.\n\n\
## Lab ideas\n- Replay a harmless connection to one of the IPs from a test machine and check the alert fires.\n- Write down which log source would have caught this story, and what you would need to turn on.\n",
        link.unwrap_or("not available"),
        iocs.ips.len(), iocs.domains.len(), iocs.sha256.len(), iocs.md5.len(),
    );

    vec![
        ("README.md".into(), readme),
        ("iocs.csv".into(), csv),
        ("suricata.rules".into(), suri),
        ("sitrep-ioc-ips".into(), ip_list),
        ("sitrep-ioc-domains".into(), dom_list),
        ("sitrep-ioc-hashes".into(), hash_list),
        ("wazuh_rules.xml".into(), wazuh),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_actor_has_a_profile() {
        for a in super::ACTORS {
            let (w, h) = super::profile(a.name);
            assert!(!w.is_empty() && !h.is_empty(), "{}", a.name);
        }
    }

    use super::*;

    #[test]
    fn canon_merges_duplicates() {
        assert_eq!(
            canon("Remote code execution (RCE)"),
            canon("remote code execution")
        );
        assert_eq!(canon("Botnets"), canon("botnet"));
        assert_ne!(canon("MFA"), canon("MFA fatigue"));
        assert!(builtin_keys().contains(&canon("RCE")));
    }

    #[test]
    fn actors_matched_as_whole_words() {
        let a = actors_in("Sandworm and Cozy Bear targeted ukraine");
        assert_eq!(
            a.iter().map(|x| x.name).collect::<Vec<_>>(),
            vec!["APT29", "Sandworm"]
        );
        assert!(actors_in("clopidogrel recall").is_empty());
        assert!(actors_in("the Cl0p gang").len() == 1);
    }

    #[test]
    fn reg_output_parsed() {
        let out = "HKEY_LOCAL_MACHINE\\SOFTWARE\\x\\7-Zip\r\n    DisplayName    REG_SZ    7-Zip 23.01 (x64)\r\n\r\nHKEY..\\y\r\n    DisplayName    REG_SZ    Mozilla Firefox (x64 en-GB)\r\n    DisplayName    REG_DWORD    0x1\r\n";
        assert_eq!(
            parse_reg_output(out),
            vec!["7-Zip 23.01 (x64)", "Mozilla Firefox (x64 en-GB)"]
        );
    }

    #[test]
    fn exposure_matching_is_careful() {
        assert!(program_matches("7-Zip 23.01 (x64)", "7-Zip", "7-Zip"));
        assert!(program_matches("Google Chrome", "Google", "Chrome"));
        assert!(!program_matches("LibreOffice", "Microsoft", "Office"));
        assert!(!program_matches("Google Chrome", "Google", "Android"));
        assert!(!program_matches("Notepad++", "Microsoft", "Windows"));
        // short generic product word needs the vendor
        assert!(!program_matches("Some VPN Tool", "Fortinet", "FortiOS"));
        assert!(program_matches("Zoom Workplace", "Zoom", "Zoom Client"));
        assert!(!program_matches("Anything", "V", "A"));
    }

    #[test]
    fn exposure_groups_cves_per_program() {
        let kev = vec![
            KevRow {
                cve: "CVE-2026-1".into(),
                vendor: "7-Zip".into(),
                product: "7-Zip".into(),
                date_added: "2026-10-01".into(),
                ransomware: false,
            },
            KevRow {
                cve: "CVE-2026-2".into(),
                vendor: "7-Zip".into(),
                product: "7-Zip".into(),
                date_added: "2026-10-05".into(),
                ransomware: true,
            },
            KevRow {
                cve: "CVE-2026-3".into(),
                vendor: "Acme".into(),
                product: "Widget Pro".into(),
                date_added: "2026-10-05".into(),
                ransomware: false,
            },
        ];
        let e = exposure(&["7-Zip 23.01".into(), "Firefox".into()], &kev);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].cves.len(), 2);
        assert_eq!(e[0].latest_added, "2026-10-05");
        assert!(e[0].ransomware);
    }

    #[test]
    fn iocs_extracted_and_filtered() {
        let t = "C2 at 8.8.4.4 and 185.220.101[.]5, internal 192.168.1.5 and 10.0.0.1, version 1.2.3.4.5 \
                 domain evil-site[.]ru and www.microsoft.com, file report.exe, hxxps://bad[.]xyz/a. \
                 hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f md5 d41d8cd98f00b204e9800998ecf8427e";
        let i = extract_iocs(t);
        assert!(
            i.ips.contains(&"8.8.4.4".to_string()) && i.ips.contains(&"185.220.101.5".to_string())
        );
        assert!(!i
            .ips
            .iter()
            .any(|x| x.starts_with("192.168") || x.starts_with("10.")));
        assert!(
            i.domains.contains(&"evil-site.ru".to_string())
                && i.domains.contains(&"bad.xyz".to_string())
        );
        assert!(!i
            .domains
            .iter()
            .any(|d| d.contains("microsoft") || d.ends_with(".exe")));
        assert_eq!(i.sha256.len(), 1);
        assert_eq!(i.md5.len(), 1);
    }

    #[test]
    fn ioc_lists_are_capped() {
        let t: String = (1..200)
            .map(|n| format!("45.33.{}.{} ", n % 250 + 1, n % 200 + 1))
            .collect();
        assert!(extract_iocs(&t).ips.len() <= IOC_CAP);
    }

    #[test]
    fn lab_pack_has_all_files_and_safe_values() {
        let i = Iocs {
            ips: vec!["8.8.4.4".into()],
            domains: vec!["evil.ru".into(), "bad\"; sid:1;)".into()],
            sha256: vec![],
            md5: vec![],
        };
        let files = lab_pack_files(
            "Big <b>attack</b>",
            Some("https://x.example/a"),
            &["CVE-2026-1".into()],
            &i,
            "2026-10-09",
        );
        let names: Vec<_> = files.iter().map(|f| f.0.as_str()).collect();
        assert_eq!(
            names,
            [
                "README.md",
                "iocs.csv",
                "suricata.rules",
                "sitrep-ioc-ips",
                "sitrep-ioc-domains",
                "sitrep-ioc-hashes",
                "wazuh_rules.xml"
            ]
        );
        let rules = &files[2].1;
        assert!(rules.contains("sid:9100000") && rules.contains("evil.ru"));
        assert!(!rules.contains("sid:1;)") && !rules.contains("<b>"));
        assert!(files[0].1.contains("LAB") || files[0].1.contains("lab"));
    }

    #[test]
    fn glossary_cap_merge_and_expiry() {
        let st = Store::open_in_memory().unwrap();
        let t = |n: &str| AiTerm {
            term: n.into(),
            plain: format!("{n} explained"),
        };
        add_ai_terms(
            &st,
            &[
                t("Botnet"),
                t("Remote code execution"),
                t("Kerberoasting"),
                t("kerberoasting"),
            ],
            1000,
        );
        let v = glossary_view(&st);
        assert_eq!(v.iter().filter(|e| e.origin == "ai").count(), 1);
        let many: Vec<AiTerm> = (0..30).map(|n| t(&format!("Zzterm{n}x"))).collect();
        add_ai_terms(&st, &many, 1001);
        assert_eq!(st.gloss_ai_active(), AI_TERM_CAP);
        set_gloss_status(&st, &canon("Kerberoasting"), "known", 1002).unwrap();
        assert!(st.gloss_ai_active() < AI_TERM_CAP);
        assert!(set_gloss_status(&st, "nope", "known", 1).is_err());
        assert!(set_gloss_status(&st, &canon("Botnet"), "'; DROP", 1).is_err());
        set_gloss_status(&st, &canon("Botnet"), "learning", 1).unwrap();
        assert_eq!(
            glossary_view(&st)
                .iter()
                .find(|e| e.term == "Botnet")
                .unwrap()
                .status,
            "learning"
        );
        st.gloss_expire(1000 + 31 * DAY).unwrap();
        assert!(glossary_view(&st)
            .iter()
            .filter(|e| e.origin == "ai")
            .all(|e| e.status == "known"));
    }

    #[test]
    fn clusters_number_days_and_flag_new() {
        use crate::feeds::RawItem;
        let st = Store::open_in_memory().unwrap();
        let mk = |title: &str, cve: &[&str], ts: i64| RawItem {
            title: title.into(),
            link: Some(format!("https://example.org/{}", ts)),
            summary: "x".into(),
            published: ts,
            source_id: "s".into(),
            source_name: "S".into(),
            cves: cve.iter().map(|c| c.to_string()).collect(),
        };
        let now = 1_791_500_000;
        st.upsert_items(
            &[
                mk("Zero-day hits VPN appliances", &["CVE-2026-7"], now - 3 * DAY),
                mk("Vendor ships patch for VPN bug", &["CVE-2026-7"], now - DAY),
                mk("Totally different gardening story", &[], now - 100),
            ],
            now,
        )
        .unwrap();
        let first = st
            .stories_since(0)
            .unwrap()
            .into_iter()
            .find(|s| s.title.starts_with("Zero-day"))
            .unwrap();
        let mut read = HashSet::new();
        read.insert(first.id);
        let c = clusters(&st, &read, 0);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].items.len(), 2);
        assert_eq!(c[0].items[0].day, 1);
        assert_eq!(c[0].items[1].day, 3);
        assert!(!c[0].items[0].new && c[0].items[1].new);
        assert_eq!(c[0].new_count, 1);
    }

    #[test]
    fn developing_links_same_cve_and_similar_titles() {
        use crate::feeds::RawItem;
        let st = Store::open_in_memory().unwrap();
        let mk = |title: &str, cve: &[&str], ts: i64| RawItem {
            title: title.into(),
            link: Some(format!(
                "https://example.org/{}",
                title.len() * 7 + ts as usize
            )),
            summary: "x".into(),
            published: ts,
            source_id: "s".into(),
            source_name: "S".into(),
            cves: cve.iter().map(|c| c.to_string()).collect(),
        };
        let now = 1_791_500_000;
        st.upsert_items(
            &[
                mk(
                    "Fortinet VPN flaw exploited in the wild",
                    &["CVE-2026-9"],
                    now - 3000,
                ),
                mk(
                    "Patch advice after attacks on appliances",
                    &["CVE-2026-9"],
                    now - 2000,
                ),
                mk(
                    "Fortinet VPN flaw exploited by ransomware crews",
                    &[],
                    now - 1000,
                ),
                mk("Unrelated Windows update news roundup", &[], now - 500),
            ],
            now,
        )
        .unwrap();
        let all = st.stories_since(0).unwrap();
        let a = all
            .iter()
            .find(|s| s.title.starts_with("Fortinet VPN flaw exploited in"))
            .unwrap();
        let dev = developing(&st, a);
        let titles: Vec<_> = dev.iter().map(|t| t.title.as_str()).collect();
        assert_eq!(
            titles,
            vec![
                "Patch advice after attacks on appliances",
                "Fortinet VPN flaw exploited by ransomware crews"
            ]
        );
    }
}
