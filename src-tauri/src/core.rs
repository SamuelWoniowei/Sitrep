//! App logic that turns stored stories into the daily brief, backlog,
//! project of the week, quiz, recap and skills radar. Pure functions over the
//! store: no network, no UI, fully unit-tested.

use chrono::{Datelike, Local, NaiveDate, TimeZone};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::ai::{AiRole, AiSummary, AiTerm};
use crate::glossary::{self, Term, TERMS};
use crate::store::{Store, StoryRow};
use crate::text::{first_sentences, truncate_chars};
use crate::themes::{self, categorize, project_for, themes_of, Category, Theme, ALL_THEMES};

const HOUR: i64 = 3600;
const DAY: i64 = 86_400;
pub const BRIEF_SIZE: usize = 3;

pub fn day_key(ts: i64) -> String {
    Local
        .timestamp_opt(ts, 0)
        .single()
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

pub fn week_key(ts: i64) -> String {
    let d = Local
        .timestamp_opt(ts, 0)
        .single()
        .unwrap_or_else(Local::now);
    let w = d.iso_week();
    format!("{}-W{:02}", w.year(), w.week())
}

fn seed(s: &str) -> u64 {
    let h = Sha256::digest(s.as_bytes());
    u64::from_le_bytes(h[..8].try_into().unwrap())
}

fn text_of(s: &StoryRow) -> String {
    format!("{} {}", s.title, s.summary)
}

pub fn watch_hits(s: &StoryRow, watch: &[String]) -> Vec<String> {
    let t = format!(" {} ", text_of(s).to_lowercase());
    watch
        .iter()
        .filter(|w| t.contains(&w.to_lowercase()))
        .cloned()
        .collect()
}

fn in_kev(store: &Store, s: &StoryRow) -> bool {
    s.cves.iter().any(|c| store.in_kev(c))
}

pub fn category_of(store: &Store, s: &StoryRow) -> Category {
    categorize(&text_of(s), in_kev(store, s), s.uk)
}

pub fn score(store: &Store, s: &StoryRow, watch: &[String], now: i64) -> f64 {
    let cat = category_of(store, s);
    let mut sc = match cat {
        Category::ExploitedNow => 50.0,
        Category::BigIncident => 30.0,
        Category::Uk => 20.0,
        Category::News => 0.0,
    };
    if !watch_hits(s, watch).is_empty() {
        sc += 25.0;
    }
    sc += (s.sources.len().saturating_sub(1) as f64) * 10.0;
    let age_h = ((now - s.published).max(0) / HOUR) as f64;
    sc - age_h * 0.5
}

/// Choose today's 3 stories: highest scores, at most 2 per category, and a UK
/// story included when one is available.
pub fn select_brief(store: &Store, now: i64) -> Vec<String> {
    let watch = store.watchlist().unwrap_or_default();
    // Stories that led an earlier day's brief only come back if nothing fresher is available.
    let seen = store.past_brief_ids(&day_key(now));
    let mut cands = Vec::new();
    for window in [48, 96, 168] {
        cands = store.stories_since(now - window * HOUR).unwrap_or_default();
        if cands.len() >= BRIEF_SIZE {
            break;
        }
    }
    let mut scored: Vec<(f64, Category, StoryRow)> = cands
        .into_iter()
        .map(|s| {
            let stale = if seen.contains(&s.id) { 1000.0 } else { 0.0 };
            (
                score(store, &s, &watch, now) - stale,
                category_of(store, &s),
                s,
            )
        })
        .collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    let mut picked: Vec<(Category, String)> = Vec::new();
    for (_, cat, s) in &scored {
        if picked.len() >= BRIEF_SIZE {
            break;
        }
        if picked.iter().filter(|(c, _)| c == cat).count() < 2 {
            picked.push((*cat, s.id.clone()));
        }
    }
    if picked.len() == BRIEF_SIZE && !picked.iter().any(|(c, _)| *c == Category::Uk) {
        if let Some((_, _, uk)) = scored.iter().find(|(_, c, _)| *c == Category::Uk) {
            picked[BRIEF_SIZE - 1] = (Category::Uk, uk.id.clone());
        }
    }
    picked.into_iter().map(|(_, id)| id).collect()
}

/// Build (or keep) today's brief and add its lab ideas to the backlog.
pub fn ensure_brief(store: &Store, now: i64) -> Vec<String> {
    let day = day_key(now);
    if let Some(ids) = store.brief_ids(&day) {
        if ids.len() >= BRIEF_SIZE {
            return ids;
        }
    }
    let ids = select_brief(store, now);
    if !ids.is_empty() {
        let _ = store.set_brief(&day, &ids);
        for id in &ids {
            if let Ok(Some(s)) = store.story(id) {
                // Only stories with a clear technical theme produce a lab idea.
                if let Some(theme) = themes_of(&text_of(&s)).into_iter().next() {
                    let idea = themes::idea_for(theme);
                    let _ = store.add_idea(idea.title, idea.detail, theme.key(), Some(id), now);
                }
            }
        }
    }
    ids
}

#[derive(Serialize, Clone, Debug)]
pub struct StoryCard {
    pub id: String,
    pub category: Category,
    pub category_label: &'static str,
    pub sources: Vec<String>,
    pub published: i64,
    pub original_title: String,
    pub headline: String,
    pub tldr: String,
    pub why: String,
    pub deeper: String,
    pub gist: String,
    pub plain: String,
    pub action: String,
    pub basis: String,
    pub roles: Vec<AiRole>,
    pub cvss: Vec<CveScore>,
    pub developing: Vec<crate::intel::TimelineItem>,
    pub actors: Vec<&'static str>,
    pub terms: Vec<AiTerm>,
    pub cves: Vec<String>,
    pub watch_hits: Vec<String>,
    pub ai: bool,
    pub read: bool,
    pub has_link: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct CveScore {
    pub cve: String,
    pub score: f64,
    pub severity: String,
    pub exploited: bool,
}

pub fn fallback_summary(store: &Store, s: &StoryRow, cat: Category) -> AiSummary {
    let mut tldr = first_sentences(&s.summary, 2);
    if tldr.is_empty() {
        tldr = "The source didn't include a summary. Open the full story for details.".into();
    }
    let mut deeper = truncate_chars(&s.summary, 900);
    for c in s.cves.iter().take(5) {
        if store.in_kev(c) {
            deeper.push_str(&format!(
                " {c} is on CISA's Known Exploited Vulnerabilities list."
            ));
        } else {
            deeper.push_str(&format!(" Tracked as {c}."));
        }
    }
    AiSummary {
        headline: s.title.clone(),
        tldr: truncate_chars(&tldr, 400),
        why: themes::why_it_matters(cat, &themes_of(&text_of(s))),
        deeper,
        gist: String::new(),
        plain: String::new(),
        action: String::new(),
        basis: String::new(),
        roles: Vec::new(),
        terms: glossary::terms_in(&text_of(s), 3)
            .into_iter()
            .map(|t| AiTerm {
                term: t.term.into(),
                plain: t.plain.into(),
            })
            .collect(),
    }
}

pub fn story_card(store: &Store, s: &StoryRow, watch: &[String], read: bool) -> StoryCard {
    let cat = category_of(store, s);
    let fallback = fallback_summary(store, s, cat);
    let ai = store
        .ai_json(&s.id)
        .and_then(|j| serde_json::from_str::<AiSummary>(&j).ok());
    let has_ai = ai.is_some();
    let mut sum = ai.unwrap_or_else(|| fallback.clone());
    if sum.terms.is_empty() {
        sum.terms = fallback.terms;
    }
    StoryCard {
        id: s.id.clone(),
        category: cat,
        category_label: cat.label(),
        sources: s.sources.clone(),
        published: s.published,
        original_title: s.title.clone(),
        headline: sum.headline,
        tldr: sum.tldr,
        why: sum.why,
        deeper: sum.deeper,
        gist: sum.gist,
        plain: sum.plain,
        action: sum.action,
        basis: sum.basis,
        roles: sum.roles,
        cvss: s
            .cves
            .iter()
            .take(5)
            .filter_map(|c| {
                store.cvss(c).map(|(score, severity)| CveScore {
                    cve: c.clone(),
                    score,
                    severity,
                    exploited: store.in_kev(c),
                })
            })
            .collect(),
        developing: crate::intel::developing(store, s),
        actors: crate::intel::actors_in(&text_of(s))
            .into_iter()
            .map(|a| a.name)
            .collect(),
        terms: sum.terms,
        cves: s.cves.clone(),
        watch_hits: watch_hits(s, watch),
        ai: has_ai,
        read,
        has_link: s.link.is_some(),
    }
}

pub fn streak(store: &Store, now: i64) -> i64 {
    let days = store.read_days().unwrap_or_default();
    let set: std::collections::HashSet<String> = days.into_iter().collect();
    let mut d = Local
        .timestamp_opt(now, 0)
        .single()
        .map(|d| d.date_naive())
        .unwrap_or_default();
    if !set.contains(&d.format("%Y-%m-%d").to_string()) {
        d = d.pred_opt().unwrap_or(d); // today not read yet: streak still alive
    }
    let mut n = 0;
    while set.contains(&d.format("%Y-%m-%d").to_string()) {
        n += 1;
        d = match d.pred_opt() {
            Some(p) => p,
            None => break,
        };
    }
    n
}

// ---------------- term of the day & quiz ----------------

pub fn term_of_day(store: &Store, brief: &[StoryRow], now: i64) -> &'static Term {
    for s in brief {
        if let Some(t) = glossary::terms_in(&text_of(s), 3)
            .into_iter()
            .find(|t| t.term != "Patch" && t.term != "Vulnerability")
        {
            return t;
        }
    }
    let _ = store;
    &TERMS[(seed(&day_key(now)) % TERMS.len() as u64) as usize]
}

#[derive(Serialize, Clone, Debug)]
pub struct QuizView {
    pub day: String,
    pub question: String,
    pub options: Vec<String>,
    pub chosen: Option<i64>,
    pub answer: Option<i64>, // only revealed after answering
    pub explanation: Option<String>,
}

pub fn make_options(term: &Term, s: u64) -> (Vec<String>, i64) {
    let mut others: Vec<&Term> = TERMS.iter().filter(|t| t.term != term.term).collect();
    let n = others.len();
    let a = others.remove((s % n as u64) as usize);
    let b = others.remove(((s / 7) % (n as u64 - 1)) as usize);
    let mut opts = vec![
        term.plain.to_string(),
        a.plain.to_string(),
        b.plain.to_string(),
    ];
    let correct_pos = (s % 3) as usize;
    opts.swap(0, correct_pos);
    (opts, correct_pos as i64)
}

pub fn quiz(store: &Store, now: i64) -> Option<QuizView> {
    let day = day_key(now);
    if store.quiz(&day).ok().flatten().is_none() {
        let s = seed(&format!("quiz{day}"));
        let missed = store.missed_terms(10).unwrap_or_default();
        let term = if !missed.is_empty() && s % 2 == 0 {
            glossary::find(&missed[(s % missed.len() as u64) as usize])
        } else {
            None
        }
        .unwrap_or(&TERMS[(s % TERMS.len() as u64) as usize]);
        let (opts, ans) = make_options(term, s);
        store
            .set_quiz(&day, term.term, &serde_json::to_string(&opts).ok()?, ans)
            .ok()?;
    }
    let (term, opts, answer, chosen) = store.quiz(&day).ok()??;
    let options: Vec<String> = serde_json::from_str(&opts).ok()?;
    let t = glossary::find(&term);
    Some(QuizView {
        day,
        question: format!("What does \"{term}\" mean?"),
        options,
        chosen,
        answer: chosen.map(|_| answer),
        explanation: chosen.and(t.map(|t| format!("{} {}", t.plain, t.analogy))),
    })
}

// ---------------- project of the week ----------------

#[derive(Serialize, Clone, Debug)]
pub struct ProjectView {
    pub week: String,
    pub plan: themes::ProjectPlan,
    pub resources: Vec<Vec<themes::Res>>,
    pub done: Vec<bool>,
    pub completed: bool,
    pub completed_at: Option<i64>,
    pub skips: SkipInfo,
}

#[derive(Serialize, Clone, Debug)]
pub struct SkipItem {
    pub week: String,
    pub title: String,
    pub mode: String,
    pub reason: String,
}

/// An honest record of skipped projects, so avoiding shows up as a pattern
/// rather than hiding.
#[derive(Serialize, Clone, Debug)]
pub struct SkipInfo {
    pub rested: bool,
    pub swaps_this_week: u32,
    pub skipped_8: u32,
    pub built_8: u32,
    pub history: Vec<SkipItem>,
}

pub const SKIP_REASONS: &[&str] = &["too_big", "not_interested", "no_time", "avoiding", "none"];

fn skip_info(store: &Store, week: &str, now: i64) -> SkipInfo {
    let recent: Vec<String> = (0..8).map(|k| week_key(now - k * 7 * DAY)).collect();
    let all = store.skips(200).unwrap_or_default();
    let mut weeks: Vec<&str> = all
        .iter()
        .map(|r| r.0.as_str())
        .filter(|w| recent.iter().any(|x| x == w))
        .collect();
    weeks.sort();
    weeks.dedup();
    let built_8 = store
        .completed_projects()
        .unwrap_or_default()
        .iter()
        .filter(|(w, _, _)| recent.iter().any(|x| x == w))
        .count() as u32;
    SkipInfo {
        rested: store.week_rested(week).unwrap_or(false),
        swaps_this_week: all.iter().filter(|r| r.0 == week && r.2 == "swap").count() as u32,
        skipped_8: weeks.len() as u32,
        built_8,
        history: all
            .into_iter()
            .take(6)
            .map(|(week, title, mode, reason, _)| SkipItem {
                week,
                title,
                mode,
                reason,
            })
            .collect(),
    }
}

pub fn week_theme(store: &Store, now: i64) -> (Theme, usize) {
    week_theme_excluding(store, now, &[])
}

/// Like `week_theme`, but never picks a theme in `skip` (unless every theme
/// has been skipped, in which case the exclusion is ignored).
pub fn week_theme_excluding(store: &Store, now: i64, skip: &[Theme]) -> (Theme, usize) {
    let stories = store.stories_since(now - 7 * DAY).unwrap_or_default();
    let mut counts: Vec<(Theme, usize)> = ALL_THEMES
        .iter()
        .filter(|t| !skip.contains(t))
        .map(|t| (*t, 0))
        .collect();
    if counts.is_empty() {
        counts = ALL_THEMES.iter().map(|t| (*t, 0)).collect();
    }
    for s in &stories {
        for t in themes_of(&text_of(s)) {
            if let Some(c) = counts.iter_mut().find(|(x, _)| *x == t) {
                c.1 += 1;
            }
        }
    }
    // "Patching" matches almost everything; prefer a specific theme.
    counts.sort_by(|a, b| {
        let pa = (a.0 != Theme::Patching, a.1);
        let pb = (b.0 != Theme::Patching, b.1);
        pb.1.cmp(&pa.1).then(pb.0.cmp(&pa.0))
    });
    let specific = counts
        .iter()
        .find(|(t, n)| *t != Theme::Patching && *n >= 2)
        .copied();
    specific.unwrap_or(counts[0])
}

/// Minimum stories in the past week before a project is locked in for the
/// week. Below that, a provisional project is shown and can still change as
/// news arrives (e.g. on a fresh install).
pub const MIN_STORIES_FOR_PROJECT: usize = 5;

pub fn project(store: &Store, now: i64) -> Option<ProjectView> {
    project_inner(store, now, false)
}

/// Same as `project`, but always locks the week's project in (used as soon as
/// the user starts working on it).
pub fn project_saved(store: &Store, now: i64) -> Option<ProjectView> {
    project_inner(store, now, true)
}

fn project_inner(store: &Store, now: i64, persist: bool) -> Option<ProjectView> {
    let week = week_key(now);
    if store.project(&week).ok()?.is_none() {
        let skipped: Vec<Theme> = store
            .week_skip_themes(&week)
            .unwrap_or_default()
            .iter()
            .filter_map(|k| Theme::from_key(k))
            .collect();
        let (theme, n) = week_theme_excluding(store, now, &skipped);
        let mut plan = project_for(theme, n);
        if n == 0 {
            plan.why =
                "A solid starter project while your news history builds up. Weekend-sized.".into();
        }
        let done = vec![false; plan.steps.len()];
        let enough = store
            .stories_since(now - 7 * DAY)
            .map(|v| v.len())
            .unwrap_or(0)
            >= MIN_STORIES_FOR_PROJECT;
        if !(persist || enough) {
            let skips = skip_info(store, &week, now);
            return Some(ProjectView {
                week,
                resources: themes::resources_for(&plan.theme),
                skips,
                plan,
                done,
                completed: false,
                completed_at: None,
            });
        }
        store
            .set_project(
                &week,
                &serde_json::to_string(&plan).ok()?,
                &serde_json::to_string(&done).ok()?,
            )
            .ok()?;
    }
    let (plan, done, completed, completed_at) = store.project(&week).ok()??;
    let plan: themes::ProjectPlan = serde_json::from_str(&plan).ok()?;
    let skips = skip_info(store, &week, now);
    Some(ProjectView {
        week,
        resources: themes::resources_for(&plan.theme),
        skips,
        plan,
        done: serde_json::from_str(&done).ok()?,
        completed,
        completed_at,
    })
}

/// Skip the week's project. `swap` replaces it with a different theme's
/// project; `rest` keeps it but marks the week as deliberately skipped. Both
/// are recorded with a reason from a fixed list. A built project can't be skipped.
pub fn skip_project(
    store: &Store,
    now: i64,
    mode: &str,
    reason: &str,
) -> Result<Option<ProjectView>, String> {
    if mode != "swap" && mode != "rest" {
        return Err("unknown skip mode".into());
    }
    if !SKIP_REASONS.contains(&reason) {
        return Err("unknown reason".into());
    }
    let cur = project_saved(store, now).ok_or("no project this week")?;
    if cur.completed {
        return Err("This project is already built.".into());
    }
    if mode == "rest" && cur.skips.rested {
        return Ok(Some(cur));
    }
    store
        .add_skip(
            &cur.week,
            &cur.plan.theme,
            &cur.plan.title,
            mode,
            reason,
            now,
        )
        .map_err(|e| e.to_string())?;
    if mode == "swap" {
        store
            .drop_unfinished_project(&cur.week)
            .map_err(|e| e.to_string())?;
        return Ok(project_saved(store, now));
    }
    Ok(project(store, now))
}

/// Undo a "skip this week".
pub fn unrest_project(store: &Store, now: i64) -> Option<ProjectView> {
    let _ = store.clear_rest(&week_key(now));
    project(store, now)
}

pub fn toggle_step(store: &Store, now: i64, step: usize) -> Option<ProjectView> {
    let p = project_saved(store, now)?;
    let mut done = p.done.clone();
    if step >= done.len() {
        return Some(p);
    }
    done[step] = !done[step];
    store
        .update_project_done(&p.week, &serde_json::to_string(&done).ok()?)
        .ok()?;
    project(store, now)
}

#[derive(Serialize, Clone, Debug)]
pub struct BuiltItem {
    pub week: String,
    pub title: String,
    pub theme: String,
    pub completed_at: i64,
}

pub fn built(store: &Store) -> Vec<BuiltItem> {
    store
        .completed_projects()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(week, plan, at)| {
            let p: themes::ProjectPlan = serde_json::from_str(&plan).ok()?;
            Some(BuiltItem {
                week,
                title: p.title,
                theme: p.theme,
                completed_at: at,
            })
        })
        .collect()
}

// ---------------- weekly recap & skills radar ----------------

#[derive(Serialize, Clone, Debug)]
pub struct RecapTheme {
    pub theme: String,
    pub count: usize,
    pub examples: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct RecapQuestion {
    pub question: String,
    pub options: Vec<String>,
    pub answer: i64,
    pub explanation: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Recap {
    pub ready: bool,
    pub days_until: i64,
    pub story_count: usize,
    pub themes: Vec<RecapTheme>,
    pub questions: Vec<RecapQuestion>,
}

pub fn recap(store: &Store, now: i64) -> Recap {
    let stories = store.stories_since(now - 7 * DAY).unwrap_or_default();
    let mut map: Vec<(Theme, Vec<String>)> = Vec::new();
    for s in &stories {
        if let Some(t) = themes_of(&text_of(s))
            .into_iter()
            .find(|t| *t != Theme::Patching)
        {
            match map.iter_mut().find(|(x, _)| *x == t) {
                Some(e) => e.1.push(s.title.clone()),
                None => map.push((t, vec![s.title.clone()])),
            }
        }
    }
    map.sort_by_key(|e| std::cmp::Reverse(e.1.len()));
    let themes: Vec<RecapTheme> = map
        .iter()
        .take(3)
        .map(|(t, titles)| RecapTheme {
            theme: t.name().into(),
            count: titles.len(),
            examples: titles.iter().take(2).cloned().collect(),
        })
        .collect();

    let mut terms: Vec<&Term> = Vec::new();
    for s in &stories {
        for t in glossary::terms_in(&text_of(s), 3) {
            if !terms.iter().any(|x| x.term == t.term) && t.term != "Patch" {
                terms.push(t);
            }
        }
    }
    let wk = week_key(now);
    let questions = terms
        .into_iter()
        .take(3)
        .map(|t| {
            let (options, answer) = make_options(t, seed(&format!("{wk}{}", t.term)));
            RecapQuestion {
                question: format!("What does \"{}\" mean?", t.term),
                options,
                answer,
                explanation: format!("{} {}", t.plain, t.analogy),
            }
        })
        .collect();

    let weekday = Local
        .timestamp_opt(now, 0)
        .single()
        .map(|d| d.weekday().num_days_from_sunday() as i64)
        .unwrap_or(0);
    Recap {
        ready: weekday == 0,
        days_until: (7 - weekday) % 7,
        story_count: stories.len(),
        themes,
        questions,
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct RadarRow {
    pub theme: String,
    pub key: String,
    pub mentions: usize,
    pub built: bool,
}

pub fn radar(store: &Store, now: i64) -> Vec<RadarRow> {
    let stories = store.stories_since(now - 30 * DAY).unwrap_or_default();
    let built_keys: Vec<String> = built(store).into_iter().map(|b| b.theme).collect();
    let mut rows: Vec<RadarRow> = ALL_THEMES
        .iter()
        .map(|t| RadarRow {
            theme: t.name().into(),
            key: t.key().into(),
            mentions: stories
                .iter()
                .filter(|s| themes_of(&text_of(s)).contains(t))
                .count(),
            built: built_keys.iter().any(|k| k == t.key()),
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.mentions));
    rows
}

pub fn kev_recent_count(store: &Store, now: i64) -> i64 {
    let since = NaiveDate::from_ymd_opt(1970, 1, 1)
        .and_then(|_| Local.timestamp_opt(now - 7 * DAY, 0).single())
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default();
    store.kev_added_since(&since)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::{KevEntry, RawItem};

    const NOW: i64 = 1_791_500_000;

    fn item(title: &str, summary: &str, src: &str, age_h: i64) -> RawItem {
        RawItem {
            title: title.into(),
            link: Some(format!("https://example.org/{}", title.len())),
            summary: summary.into(),
            published: NOW - age_h * HOUR,
            source_id: src.into(),
            source_name: src.into(),
            cves: crate::feeds::extract_cves(&format!("{title} {summary}")),
        }
    }

    fn seeded() -> Store {
        let s = Store::open_in_memory().unwrap();
        s.upsert_items(
            &[
                item("Vendor launches shiny dashboard", "Marketing.", "a", 1),
                item(
                    "Ivanti VPN flaw CVE-2026-0001 abused",
                    "Attackers use it.",
                    "b",
                    3,
                ),
                item(
                    "Ransomware gang hits hospital group",
                    "Systems down.",
                    "c",
                    5,
                ),
                item(
                    "NCSC publishes new guidance for boards",
                    "UK advice.",
                    "ncsc",
                    10,
                ),
                item("Another product release note", "Meh.", "d", 2),
            ],
            NOW,
        )
        .unwrap();
        s.replace_kev(&[KevEntry {
            cve: "CVE-2026-0001".into(),
            vendor: "Ivanti".into(),
            product: "VPN".into(),
            name: "x".into(),
            date_added: "2026-10-08".into(),
            description: "d".into(),
            ransomware: false,
        }])
        .unwrap();
        s
    }

    #[test]
    fn brief_prioritises_exploited_incident_and_uk() {
        let s = seeded();
        let ids = select_brief(&s, NOW);
        assert_eq!(ids.len(), 3);
        let titles: Vec<String> = ids
            .iter()
            .map(|i| s.story(i).unwrap().unwrap().title)
            .collect();
        assert!(titles[0].contains("Ivanti"), "{titles:?}");
        assert!(titles.iter().any(|t| t.contains("Ransomware")));
        assert!(titles.iter().any(|t| t.contains("NCSC")));
    }

    #[test]
    fn yesterdays_brief_stories_do_not_lead_today() {
        let s = seeded();
        let first = select_brief(&s, NOW);
        // Pretend these three led yesterday's brief.
        s.set_brief(&day_key(NOW - 86_400), &first).unwrap();
        let today = select_brief(&s, NOW);
        assert_eq!(today.len(), 3);
        assert!(
            today.iter().filter(|i| first.contains(i)).count() < 3,
            "fresh stories must lead when they exist"
        );
        // The fourth story is not in yesterday's brief, so it must be picked.
        let fourth: Vec<_> = s
            .stories_since(0)
            .unwrap()
            .into_iter()
            .filter(|x| !first.contains(&x.id))
            .map(|x| x.id)
            .collect();
        assert!(fourth.iter().all(|id| today.contains(id)));
    }

    #[test]
    fn more_news_skips_todays_brief() {
        let s = seeded();
        let ids = ensure_brief(&s, NOW);
        let more = more_stories(&s, NOW, 15);
        assert!(more.iter().all(|m| !ids.contains(&m.id)));
        let all = s.stories_since(NOW - 72 * HOUR).unwrap().len();
        assert_eq!(more.len(), all - ids.len());
    }

    #[test]
    fn watchlist_boosts() {
        let s = seeded();
        s.add_watch("dashboard").unwrap();
        let st = s
            .stories_since(0)
            .unwrap()
            .into_iter()
            .find(|x| x.title.contains("dashboard"))
            .unwrap();
        assert!(score(&s, &st, &["dashboard".into()], NOW) > score(&s, &st, &[], NOW));
    }

    #[test]
    fn ensure_brief_is_stable_and_creates_ideas() {
        let s = seeded();
        let a = ensure_brief(&s, NOW);
        s.upsert_items(
            &[item(
                "Zero-day in FortiGate exploited in attacks",
                "x",
                "e",
                0,
            )],
            NOW,
        )
        .unwrap();
        let b = ensure_brief(&s, NOW + 60);
        assert_eq!(a, b, "brief must not reshuffle during the day");
        assert!(s.active_idea_count() >= 1);
    }

    #[test]
    fn fallback_summary_works_without_ai() {
        let s = seeded();
        let st = s
            .stories_since(0)
            .unwrap()
            .into_iter()
            .find(|x| x.title.contains("Ivanti"))
            .unwrap();
        let card = story_card(&s, &st, &[], false);
        assert_eq!(card.category, Category::ExploitedNow);
        assert!(!card.ai);
        assert!(card.deeper.contains("Known Exploited"));
        assert!(card.terms.iter().any(|t| t.term == "Edge device"));
    }

    #[test]
    fn quiz_hides_answer_until_answered() {
        let s = seeded();
        let q = quiz(&s, NOW).unwrap();
        assert_eq!(q.options.len(), 3);
        assert!(q.answer.is_none());
        s.answer_quiz(&q.day, 0).unwrap();
        let q2 = quiz(&s, NOW).unwrap();
        assert!(q2.answer.is_some() && q2.explanation.is_some());
    }

    #[test]
    fn options_contain_correct_answer_once() {
        for (i, t) in TERMS.iter().enumerate() {
            let (opts, ans) = make_options(t, i as u64 * 7919 + 13);
            assert_eq!(opts[ans as usize], t.plain);
            assert_eq!(opts.iter().filter(|o| *o == t.plain).count(), 1);
            let mut u = opts.clone();
            u.sort();
            u.dedup();
            assert_eq!(u.len(), 3);
        }
    }

    #[test]
    fn project_lifecycle() {
        let s = seeded();
        let p = project(&s, NOW).unwrap();
        assert_eq!(p.done, vec![false; 4]);
        let p = toggle_step(&s, NOW, 1).unwrap();
        assert!(p.done[1]);
        let p = toggle_step(&s, NOW, 99).unwrap();
        assert_eq!(p.done.len(), 4);
        s.complete_project(&p.week, true, NOW).unwrap();
        assert_eq!(built(&s).len(), 1);
        assert!(radar(&s, NOW).iter().any(|r| r.built));
    }

    #[test]
    fn skipping_swaps_the_theme_and_is_recorded() {
        let s = seeded();
        let first = project(&s, NOW).unwrap();
        let swapped = skip_project(&s, NOW, "swap", "too_big").unwrap().unwrap();
        assert_ne!(swapped.plan.theme, first.plan.theme);
        assert_eq!(swapped.skips.swaps_this_week, 1);
        assert_eq!(swapped.skips.skipped_8, 1);
        assert_eq!(swapped.skips.history[0].reason, "too_big");
        assert!(!swapped.skips.rested);
        // The new one is locked in and stable across calls.
        assert_eq!(project(&s, NOW).unwrap().plan.theme, swapped.plan.theme);
        // Swapping again never returns a theme already skipped this week.
        let third = skip_project(&s, NOW, "swap", "avoiding").unwrap().unwrap();
        assert!(![first.plan.theme.clone(), swapped.plan.theme.clone()].contains(&third.plan.theme));
    }

    #[test]
    fn resting_a_week_keeps_the_project_and_can_be_undone() {
        let s = seeded();
        let p = project(&s, NOW).unwrap();
        let r = skip_project(&s, NOW, "rest", "no_time").unwrap().unwrap();
        assert!(r.skips.rested);
        assert_eq!(r.plan.title, p.plan.title);
        assert_eq!(r.skips.skipped_8, 1);
        let back = unrest_project(&s, NOW).unwrap();
        assert!(!back.skips.rested);
        assert_eq!(back.skips.skipped_8, 0);
    }

    #[test]
    fn skip_rejects_bad_input_and_built_projects() {
        let s = seeded();
        assert!(skip_project(&s, NOW, "delete", "none").is_err());
        assert!(skip_project(&s, NOW, "swap", "<script>").is_err());
        let p = project_saved(&s, NOW).unwrap();
        s.complete_project(&p.week, true, NOW).unwrap();
        assert!(skip_project(&s, NOW, "swap", "none").is_err());
        assert_eq!(project(&s, NOW).unwrap().skips.built_8, 1);
    }

    #[test]
    fn project_stays_provisional_until_enough_news() {
        let s = Store::open_in_memory().unwrap();
        let p = project(&s, NOW).unwrap();
        assert!(
            s.project(&p.week).unwrap().is_none(),
            "empty install must not lock a project"
        );
        toggle_step(&s, NOW, 0).unwrap();
        assert!(
            s.project(&p.week).unwrap().is_some(),
            "starting work locks it in"
        );
    }

    #[test]
    fn streak_counts_consecutive_days() {
        let s = seeded();
        assert_eq!(streak(&s, NOW), 0);
        s.mark_read(&day_key(NOW - DAY), "x").unwrap();
        s.mark_read(&day_key(NOW - 2 * DAY), "x").unwrap();
        assert_eq!(streak(&s, NOW), 2);
        s.mark_read(&day_key(NOW), "x").unwrap();
        assert_eq!(streak(&s, NOW), 3);
    }

    #[test]
    fn recap_and_radar_shapes() {
        let s = seeded();
        let r = recap(&s, NOW);
        assert_eq!(r.story_count, 5);
        assert!(!r.themes.is_empty());
        for q in &r.questions {
            assert_eq!(q.options.len(), 3);
        }
        assert_eq!(radar(&s, NOW).len(), ALL_THEMES.len());
    }
}

// ---------------- more news ----------------

#[derive(Serialize, Clone, Debug)]
pub struct MoreItem {
    pub id: String,
    pub title: String,
    pub sources: Vec<String>,
    pub published: i64,
    pub category_label: &'static str,
    pub has_link: bool,
}

/// The newest stories that are not in today's brief, freshest first.
pub fn more_stories(store: &Store, now: i64, limit: usize) -> Vec<MoreItem> {
    let brief: std::collections::HashSet<String> = store
        .brief_ids(&day_key(now))
        .unwrap_or_default()
        .into_iter()
        .collect();
    store
        .stories_since(now - 72 * HOUR)
        .unwrap_or_default()
        .into_iter()
        .filter(|s| !brief.contains(&s.id))
        .take(limit)
        .map(|s| MoreItem {
            category_label: category_of(store, &s).label(),
            has_link: s.link.is_some(),
            id: s.id,
            title: crate::text::to_plain(&s.title, 200),
            sources: s.sources,
            published: s.published,
        })
        .collect()
}
