//! The only bridge between the UI and the system. Every command validates its
//! input; the UI can never pass a URL, path or SQL fragment through here.

use std::sync::Mutex;

use serde::Serialize;
use tauri::State;
use tauri_plugin_opener::OpenerExt;

use crate::ai::{self, AiSummary};
use crate::core::{self, BuiltItem, ProjectView, QuizView, RadarRow, Recap, StoryCard};
use crate::feeds;
use crate::glossary::{self, Term};
use crate::net::{self, FeedKind, SOURCES};
use crate::store::{Idea, Store};
use crate::text::to_plain;

pub struct AppState {
    pub store: Mutex<Store>,
    pub feed_client: reqwest::Client,
    pub ai_client: reqwest::Client,
    pub article_client: reqwest::Client,
}

type Res<T> = Result<T, String>;

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn lock(state: &AppState) -> Res<std::sync::MutexGuard<'_, Store>> {
    state.store.lock().map_err(|_| "internal error".to_string())
}

fn valid_story_id(id: &str) -> Res<()> {
    if id.len() == 24 && id.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("invalid story".into())
    }
}

/// Watchlist terms: short, simple characters only.
pub fn clean_watch_term(raw: &str) -> Res<String> {
    let t = to_plain(raw, 60).trim().to_lowercase();
    if t.is_empty() || t.chars().count() > 40 {
        return Err("Use 1 to 40 characters.".into());
    }
    if !t
        .chars()
        .all(|c| c.is_alphanumeric() || " .-+#&/".contains(c))
    {
        return Err("Use letters, numbers, spaces and . - + # & / only.".into());
    }
    Ok(t)
}

// ---------------- refresh ----------------

#[derive(Serialize)]
pub struct RefreshResult {
    pub new_stories: usize,
    pub failed: Vec<String>,
    pub skipped: bool,
}

#[tauri::command]
pub async fn refresh(state: State<'_, AppState>, force: Option<bool>) -> Res<RefreshResult> {
    let t = now();
    {
        let store = lock(&state)?;
        let last_ok: i64 = store
            .setting("last_sync")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let last_try: i64 = store
            .setting("last_attempt")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        // Be polite to sources: never more than one attempt per 2 minutes, and
        // automatic refreshes only once an hour after a successful sync.
        let skip = t - last_try < 120 || (!force.unwrap_or(false) && t - last_ok < 3600);
        if skip {
            return Ok(RefreshResult {
                new_stories: 0,
                failed: vec![],
                skipped: true,
            });
        }
        store
            .set_setting("last_attempt", &t.to_string())
            .map_err(|e| e.to_string())?;
    }

    let mut handles = Vec::new();
    for src in SOURCES {
        let client = state.feed_client.clone();
        handles.push((
            src,
            tokio::spawn(async move { net::fetch_source(&client, src).await }),
        ));
    }
    let mut items = Vec::new();
    let mut kev = None;
    let mut failed = Vec::new();
    for (src, h) in handles {
        match h.await {
            Ok(Ok(bytes)) => {
                let parsed = match src.kind {
                    FeedKind::Rss => feeds::parse_rss(&bytes, src, t).map(|v| items.extend(v)),
                    FeedKind::KevJson => feeds::parse_kev(&bytes).map(|v| kev = Some(v)),
                };
                if parsed.is_err() {
                    failed.push(src.name.to_string());
                }
            }
            _ => failed.push(src.name.to_string()),
        }
    }

    let store = lock(&state)?;
    if failed.len() < SOURCES.len() {
        store
            .set_setting("last_sync", &t.to_string())
            .map_err(|e| e.to_string())?;
    }
    if let Some(k) = kev {
        store.replace_kev(&k).map_err(|e| e.to_string())?;
    }
    let new_stories = store.upsert_items(&items, t).map_err(|e| e.to_string())?;
    let _ = store.expire_ideas(t);
    let _ = store.prune(t);
    core::ensure_brief(&store, t);
    Ok(RefreshResult {
        new_stories,
        failed,
        skipped: false,
    })
}

// ---------------- today ----------------

#[derive(Serialize)]
pub struct Today {
    pub day: String,
    pub last_sync: i64,
    pub stories: Vec<StoryCard>,
    pub read_count: usize,
    pub exploited_recent: i64,
    pub watch_hits: usize,
    pub streak: i64,
    pub term: Term,
    pub quiz: Option<QuizView>,
    pub project: Option<ProjectView>,
    pub ideas: Vec<Idea>,
    pub idea_count: i64,
    pub idea_cap: i64,
    pub recap_days_until: i64,
    pub radar_top: Vec<RadarRow>,
    pub watchlist: Vec<String>,
}

#[tauri::command]
pub fn get_today(state: State<'_, AppState>) -> Res<Today> {
    let t = now();
    let store = lock(&state)?;
    let day = core::day_key(t);
    let ids = core::ensure_brief(&store, t);
    let read = store.read_ids(&day).unwrap_or_default();
    let watch = store.watchlist().unwrap_or_default();
    let rows: Vec<_> = ids
        .iter()
        .filter_map(|id| store.story(id).ok().flatten())
        .collect();
    let stories: Vec<StoryCard> = rows
        .iter()
        .map(|s| core::story_card(&store, s, &watch, read.contains(&s.id)))
        .collect();
    let watch_hits = store
        .stories_since(t - 48 * 3600)
        .unwrap_or_default()
        .iter()
        .filter(|s| !core::watch_hits(s, &watch).is_empty())
        .count();
    let ideas = store.ideas("active", t).unwrap_or_default();
    Ok(Today {
        last_sync: store
            .setting("last_sync")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        read_count: stories.iter().filter(|s| s.read).count(),
        exploited_recent: core::kev_recent_count(&store, t),
        watch_hits,
        streak: core::streak(&store, t),
        term: *core::term_of_day(&store, &rows, t),
        quiz: core::quiz(&store, t),
        project: core::project(&store, t),
        idea_count: ideas.len() as i64,
        idea_cap: crate::store::BACKLOG_CAP,
        ideas: ideas.into_iter().take(3).collect(),
        recap_days_until: core::recap(&store, t).days_until,
        radar_top: core::radar(&store, t).into_iter().take(3).collect(),
        watchlist: watch,
        stories,
        day,
    })
}

#[tauri::command]
pub fn mark_read(state: State<'_, AppState>, id: String) -> Res<()> {
    valid_story_id(&id)?;
    let store = lock(&state)?;
    store
        .story(&id)
        .map_err(|e| e.to_string())?
        .ok_or("unknown story")?;
    store
        .mark_read(&core::day_key(now()), &id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn open_story(app: tauri::AppHandle, state: State<'_, AppState>, id: String) -> Res<()> {
    valid_story_id(&id)?;
    let link = {
        let store = lock(&state)?;
        store
            .story(&id)
            .map_err(|e| e.to_string())?
            .and_then(|s| s.link)
    };
    // Re-validate at the point of use, even though links were checked on import.
    let url = link
        .as_deref()
        .and_then(net::openable)
        .ok_or("This story has no safe link.")?;
    app.opener()
        .open_url(url.as_str(), None::<&str>)
        .map_err(|_| "Couldn't open the browser.".to_string())
}

// ---------------- AI ----------------

#[derive(Serialize)]
pub struct AiStatus {
    pub running: bool,
    pub enabled: bool,
    pub models: Vec<String>,
    pub model: String,
    pub full_articles: bool,
}

async fn ai_model(state: &AppState) -> Res<String> {
    let (enabled, wanted) = {
        let s = lock(state)?;
        (
            s.setting("ai_enabled").as_deref() != Some("0"),
            s.setting("ai_model")
                .unwrap_or_else(|| ai::DEFAULT_MODEL.into()),
        )
    };
    if !enabled {
        return Err("Local AI is turned off in Settings.".into());
    }
    let models = ai::list_models(&state.ai_client).await?;
    // Only ever use a model that is actually installed locally.
    // list_models never returns cloud models; this check is defence in depth.
    if models.contains(&wanted) && !ai::is_cloud_model(&wanted) {
        Ok(wanted)
    } else {
        models
            .into_iter()
            .next()
            .ok_or_else(|| "No local AI model installed.".into())
    }
}

#[tauri::command]
pub async fn ai_status(state: State<'_, AppState>) -> Res<AiStatus> {
    let (enabled, model, full_articles) = {
        let s = lock(&state)?;
        (
            s.setting("ai_enabled").as_deref() != Some("0"),
            s.setting("ai_model")
                .unwrap_or_else(|| ai::DEFAULT_MODEL.into()),
            s.setting("full_articles").as_deref() != Some("0"),
        )
    };
    match ai::list_models(&state.ai_client).await {
        Ok(models) => Ok(AiStatus {
            running: true,
            enabled,
            models,
            model,
            full_articles,
        }),
        Err(_) => Ok(AiStatus {
            running: false,
            enabled,
            models: vec![],
            model,
            full_articles,
        }),
    }
}

#[tauri::command]
pub fn set_ai(state: State<'_, AppState>, enabled: bool, model: String) -> Res<()> {
    let model = to_plain(&model, 100);
    if !model
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || ":._-/".contains(c))
    {
        return Err("invalid model name".into());
    }
    if ai::is_cloud_model(&model) {
        return Err(
            "Cloud models are blocked: they would send your data off this computer.".into(),
        );
    }
    let s = lock(&state)?;
    s.set_setting("ai_enabled", if enabled { "1" } else { "0" })
        .map_err(|e| e.to_string())?;
    s.set_setting("ai_model", &model).map_err(|e| e.to_string())
}

/// The best text available for a story: the full article if fetching is
/// enabled and the link is on an allowlisted news site, else the feed summary.
async fn article_text(state: &AppState, story: &crate::store::StoryRow) -> String {
    let (enabled, cached) = match lock(state) {
        Ok(s) => (
            s.setting("full_articles").as_deref() != Some("0"),
            s.article(&story.id),
        ),
        Err(_) => return story.summary.clone(),
    };
    if let Some(t) = cached {
        return pick_body(&t, &story.summary);
    }
    let Some(link) = story.link.as_deref() else {
        return story.summary.clone();
    };
    let allowed = url::Url::parse(link)
        .map(|u| net::article_fetchable(&u))
        .unwrap_or(false);
    if !enabled || !allowed {
        return story.summary.clone();
    }
    let Ok(bytes) = net::fetch_article(&state.article_client, link).await else {
        return story.summary.clone();
    };
    let text = crate::text::extract_article(&String::from_utf8_lossy(&bytes));
    if let Ok(s) = lock(state) {
        let _ = s.set_article(&story.id, &text, now());
    }
    pick_body(&text, &story.summary)
}

fn pick_body(article: &str, summary: &str) -> String {
    if article.chars().count() > summary.chars().count() {
        article.to_string()
    } else {
        summary.to_string()
    }
}

#[tauri::command]
pub fn set_full_articles(state: State<'_, AppState>, enabled: bool) -> Res<()> {
    lock(&state)?
        .set_setting("full_articles", if enabled { "1" } else { "0" })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn enhance_story(state: State<'_, AppState>, id: String) -> Res<StoryCard> {
    valid_story_id(&id)?;
    let (story, watch) = {
        let s = lock(&state)?;
        let st = s
            .story(&id)
            .map_err(|e| e.to_string())?
            .ok_or("unknown story")?;
        if s.ai_json(&id).is_some() {
            let read = s
                .read_ids(&core::day_key(now()))
                .unwrap_or_default()
                .contains(&id);
            return Ok(core::story_card(
                &s,
                &st,
                &s.watchlist().unwrap_or_default(),
                read,
            ));
        }
        (st, s.watchlist().unwrap_or_default())
    };
    let model = ai_model(&state).await?;
    let body = article_text(&state, &story).await;
    let n = ai::nonce();
    let prompt = ai::summary_prompt(&n, &story.title, &body, &watch);
    let raw = ai::generate(&state.ai_client, &model, &prompt).await?;
    let summary: AiSummary = ai::validate_summary(&raw)
        .ok_or("The AI gave an unusable answer; showing the source summary instead.")?;
    let s = lock(&state)?;
    s.set_ai_json(
        &id,
        &serde_json::to_string(&summary).map_err(|e| e.to_string())?,
        &model,
        now(),
    )
    .map_err(|e| e.to_string())?;
    let read = s
        .read_ids(&core::day_key(now()))
        .unwrap_or_default()
        .contains(&id);
    Ok(core::story_card(&s, &story, &watch, read))
}

#[tauri::command]
pub async fn ask_story(state: State<'_, AppState>, id: String, question: String) -> Res<String> {
    valid_story_id(&id)?;
    let q = to_plain(&question, 400);
    if q.chars().count() < 3 || question.chars().count() > 300 {
        return Err("Ask a question of 3 to 300 characters.".into());
    }
    let story = {
        let s = lock(&state)?;
        s.story(&id)
            .map_err(|e| e.to_string())?
            .ok_or("unknown story")?
    };
    let model = ai_model(&state).await?;
    let n = ai::nonce();
    let raw = ai::generate(
        &state.ai_client,
        &model,
        &ai::ask_prompt(&n, &story.title, &story.summary, &q),
    )
    .await?;
    ai::validate_answer(&raw)
        .ok_or_else(|| "The AI gave an unusable answer. Try rephrasing.".into())
}

// ---------------- backlog ----------------

#[tauri::command]
pub fn list_ideas(state: State<'_, AppState>, status: String) -> Res<Vec<Idea>> {
    if status != "active" && status != "archived" {
        return Err("invalid status".into());
    }
    let s = lock(&state)?;
    let _ = s.expire_ideas(now());
    s.ideas(&status, now()).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn star_idea(state: State<'_, AppState>, id: i64, starred: bool) -> Res<()> {
    lock(&state)?
        .set_idea_starred(id, starred)
        .map(|_| ())
        .map_err(|e| e.to_string())
}
#[tauri::command]
pub fn dismiss_idea(state: State<'_, AppState>, id: i64) -> Res<()> {
    lock(&state)?
        .dismiss_idea(id)
        .map(|_| ())
        .map_err(|e| e.to_string())
}
#[tauri::command]
pub fn restore_idea(state: State<'_, AppState>, id: i64) -> Res<bool> {
    lock(&state)?
        .restore_idea(id, now())
        .map(|n| n > 0)
        .map_err(|e| e.to_string())
}
#[tauri::command]
pub fn delete_idea(state: State<'_, AppState>, id: i64) -> Res<()> {
    lock(&state)?
        .delete_idea(id)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// ---------------- project ----------------

#[tauri::command]
pub fn get_project(state: State<'_, AppState>) -> Res<Option<ProjectView>> {
    let s = lock(&state)?;
    Ok(core::project(&s, now()))
}
#[tauri::command]
pub fn toggle_project_step(state: State<'_, AppState>, step: u32) -> Res<Option<ProjectView>> {
    let s = lock(&state)?;
    Ok(core::toggle_step(&s, now(), step as usize))
}
#[tauri::command]
pub fn complete_project(state: State<'_, AppState>, completed: bool) -> Res<Option<ProjectView>> {
    let s = lock(&state)?;
    let t = now();
    if let Some(p) = core::project_saved(&s, t) {
        s.complete_project(&p.week, completed, t)
            .map_err(|e| e.to_string())?;
    }
    Ok(core::project(&s, t))
}
#[tauri::command]
pub fn list_built(state: State<'_, AppState>) -> Res<Vec<BuiltItem>> {
    let s = lock(&state)?;
    Ok(core::built(&s))
}

// ---------------- learning ----------------

#[tauri::command]
pub fn get_glossary() -> Vec<Term> {
    let mut v = glossary::TERMS.to_vec();
    v.sort_by_key(|t| t.term.to_lowercase());
    v
}
#[tauri::command]
pub fn answer_quiz(state: State<'_, AppState>, choice: i64) -> Res<Option<QuizView>> {
    if !(0..3).contains(&choice) {
        return Err("invalid choice".into());
    }
    let s = lock(&state)?;
    let t = now();
    s.answer_quiz(&core::day_key(t), choice)
        .map_err(|e| e.to_string())?;
    Ok(core::quiz(&s, t))
}
#[tauri::command]
pub fn get_recap(state: State<'_, AppState>) -> Res<Recap> {
    let s = lock(&state)?;
    Ok(core::recap(&s, now()))
}
#[tauri::command]
pub fn get_radar(state: State<'_, AppState>) -> Res<Vec<RadarRow>> {
    let s = lock(&state)?;
    Ok(core::radar(&s, now()))
}

// ---------------- watchlist ----------------

#[tauri::command]
pub fn get_watchlist(state: State<'_, AppState>) -> Res<Vec<String>> {
    lock(&state)?.watchlist().map_err(|e| e.to_string())
}
#[tauri::command]
pub fn add_watch(state: State<'_, AppState>, term: String) -> Res<Vec<String>> {
    let t = clean_watch_term(&term)?;
    let s = lock(&state)?;
    if s.watchlist().map_err(|e| e.to_string())?.len() >= 30 {
        return Err("Watchlist is limited to 30 terms.".into());
    }
    s.add_watch(&t).map_err(|e| e.to_string())?;
    s.watchlist().map_err(|e| e.to_string())
}
#[tauri::command]
pub fn remove_watch(state: State<'_, AppState>, term: String) -> Res<Vec<String>> {
    let s = lock(&state)?;
    s.remove_watch(&term).map_err(|e| e.to_string())?;
    s.watchlist().map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct SourceInfo {
    pub name: &'static str,
    pub url: &'static str,
}

#[tauri::command]
pub fn list_sources() -> Vec<SourceInfo> {
    SOURCES
        .iter()
        .map(|s| SourceInfo {
            name: s.name,
            url: s.url,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_terms_validated() {
        assert_eq!(clean_watch_term("  Microsoft  ").unwrap(), "microsoft");
        assert_eq!(clean_watch_term("C++").unwrap(), "c++");
        assert!(clean_watch_term("").is_err());
        assert!(clean_watch_term(&"a".repeat(41)).is_err());
        assert!(clean_watch_term("x'); DROP TABLE watchlist;--").is_err());
        assert_eq!(clean_watch_term("<b>wazuh</b>").unwrap(), "wazuh");
    }

    #[test]
    fn longer_text_wins() {
        assert_eq!(
            pick_body("a long full article body", "short"),
            "a long full article body"
        );
        assert_eq!(pick_body("", "feed summary"), "feed summary");
    }

    #[test]
    fn story_ids_validated() {
        assert!(valid_story_id("0123456789abcdef01234567").is_ok());
        for bad in [
            "",
            "../../etc/passwd",
            "0123456789abcdef0123456g",
            "' OR 1=1 --",
        ] {
            assert!(valid_story_id(bad).is_err());
        }
    }
}
