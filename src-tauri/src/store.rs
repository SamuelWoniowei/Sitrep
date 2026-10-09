//! Local SQLite storage. Every query is parameterised; nothing from a feed or
//! from the UI is ever concatenated into SQL.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::feeds::{KevEntry, RawItem};
use crate::text::{jaccard, title_tokens};

pub const BACKLOG_CAP: i64 = 10;
pub const IDEA_EXPIRY_DAYS: i64 = 21;
const RETENTION_DAYS: i64 = 90;
const DAY: i64 = 86_400;

/// (plan JSON, done JSON, completed, completed_at)
pub type ProjectRow = (String, String, bool, Option<i64>);
/// (term, options JSON, answer index, chosen index)
pub type QuizRow = (String, String, i64, Option<i64>);

pub struct Store {
    pub conn: Connection,
}

#[derive(Debug, Clone)]
pub struct StoryRow {
    pub id: String,
    pub title: String,
    pub link: Option<String>,
    pub summary: String,
    pub published: i64,
    pub sources: Vec<String>,
    pub cves: Vec<String>,
    pub uk: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KevRow {
    pub cve: String,
    pub vendor: String,
    pub product: String,
    pub date_added: String,
    pub ransomware: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GlossRow {
    pub key: String,
    pub term: String,
    pub plain: String,
    pub analogy: String,
    pub status: String,
    pub origin: String,
    pub archived: bool,
    pub added: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Idea {
    pub id: i64,
    pub title: String,
    pub detail: String,
    pub theme: String,
    pub created: i64,
    pub starred: bool,
    pub status: String,
    pub reason: Option<String>,
    pub expires_in_days: Option<i64>,
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             PRAGMA secure_delete=ON;
             CREATE TABLE IF NOT EXISTS stories(
               id TEXT PRIMARY KEY, title TEXT NOT NULL, link TEXT, summary TEXT NOT NULL,
               published INTEGER NOT NULL, fetched INTEGER NOT NULL, sources TEXT NOT NULL,
               cves TEXT NOT NULL, uk INTEGER NOT NULL DEFAULT 0);
             CREATE INDEX IF NOT EXISTS stories_pub ON stories(published);
             CREATE TABLE IF NOT EXISTS kev(
               cve TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT, date_added TEXT,
               description TEXT, ransomware INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS ai(story_id TEXT PRIMARY KEY, json TEXT NOT NULL, model TEXT, created INTEGER);
             CREATE TABLE IF NOT EXISTS articles(story_id TEXT PRIMARY KEY, text TEXT NOT NULL, fetched INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS briefs(day TEXT PRIMARY KEY, ids TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS reads(day TEXT NOT NULL, story_id TEXT NOT NULL, PRIMARY KEY(day, story_id));
             CREATE TABLE IF NOT EXISTS ideas(
               id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, detail TEXT NOT NULL,
               theme TEXT NOT NULL, story_id TEXT, created INTEGER NOT NULL,
               starred INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'active', reason TEXT);
             CREATE TABLE IF NOT EXISTS projects(
               week TEXT PRIMARY KEY, plan TEXT NOT NULL, done TEXT NOT NULL,
               completed INTEGER NOT NULL DEFAULT 0, completed_at INTEGER);
             CREATE TABLE IF NOT EXISTS watchlist(term TEXT PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS cvss(cve TEXT PRIMARY KEY, score REAL NOT NULL, severity TEXT NOT NULL, fetched INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS gloss(
               key TEXT PRIMARY KEY, term TEXT NOT NULL, plain TEXT NOT NULL, analogy TEXT NOT NULL DEFAULT '',
               status TEXT NOT NULL DEFAULT 'new', origin TEXT NOT NULL, archived INTEGER NOT NULL DEFAULT 0,
               added INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS quiz(day TEXT PRIMARY KEY, term TEXT NOT NULL, options TEXT NOT NULL, answer INTEGER NOT NULL, chosen INTEGER);",
        )?;
        Ok(Store { conn })
    }

    // ---------- settings ----------
    pub fn setting(&self, key: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT value FROM settings WHERE key=?1",
                params![key],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }
    pub fn set_setting(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    // ---------- stories ----------
    pub fn upsert_items(&self, items: &[RawItem], now: i64) -> rusqlite::Result<usize> {
        let recent = self.stories_since(now - 4 * DAY)?;
        let mut recent_tokens: Vec<(StoryRow, Vec<String>)> = recent
            .into_iter()
            .map(|s| {
                let t = title_tokens(&s.title);
                (s, t)
            })
            .collect();
        let mut new = 0;
        for it in items {
            let tokens = title_tokens(&it.title);
            let dup = recent_tokens.iter_mut().find(|(s, t)| {
                (it.link.is_some() && s.link == it.link) || jaccard(t, &tokens) >= 0.6
            });
            if let Some((s, _)) = dup {
                let mut changed = false;
                if !s.sources.contains(&it.source_name) {
                    s.sources.push(it.source_name.clone());
                    changed = true;
                }
                for c in &it.cves {
                    if !s.cves.contains(c) {
                        s.cves.push(c.clone());
                        changed = true;
                    }
                }
                if it.summary.len() > s.summary.len() {
                    s.summary = it.summary.clone();
                    changed = true;
                }
                if changed {
                    self.conn.execute(
                        "UPDATE stories SET sources=?2, cves=?3, summary=?4 WHERE id=?1",
                        params![s.id, json(&s.sources), json(&s.cves), s.summary],
                    )?;
                }
                continue;
            }
            let id = story_id(it.link.as_deref().unwrap_or(&it.title));
            let row = StoryRow {
                id: id.clone(),
                title: it.title.clone(),
                link: it.link.clone(),
                summary: it.summary.clone(),
                published: it.published,
                sources: vec![it.source_name.clone()],
                cves: it.cves.clone(),
                uk: it.source_id == "ncsc",
            };
            let inserted = self.conn.execute(
                "INSERT OR IGNORE INTO stories(id,title,link,summary,published,fetched,sources,cves,uk)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![row.id, row.title, row.link, row.summary, row.published, now, json(&row.sources), json(&row.cves), row.uk as i64],
            )?;
            if inserted > 0 {
                new += 1;
                recent_tokens.push((row, tokens));
            }
        }
        Ok(new)
    }

    pub fn stories_since(&self, since: i64) -> rusqlite::Result<Vec<StoryRow>> {
        let mut st = self.conn.prepare(
            "SELECT id,title,link,summary,published,sources,cves,uk FROM stories WHERE published>=?1 ORDER BY published DESC LIMIT 2000",
        )?;
        let rows = st.query_map(params![since], row_to_story)?;
        rows.collect()
    }

    pub fn story(&self, id: &str) -> rusqlite::Result<Option<StoryRow>> {
        self.conn
            .query_row(
                "SELECT id,title,link,summary,published,sources,cves,uk FROM stories WHERE id=?1",
                params![id],
                row_to_story,
            )
            .optional()
    }

    pub fn prune(&self, now: i64) -> rusqlite::Result<()> {
        let cutoff = now - RETENTION_DAYS * DAY;
        self.conn.execute(
            "DELETE FROM articles WHERE story_id IN (SELECT id FROM stories WHERE published<?1)",
            params![cutoff],
        )?;
        self.conn.execute(
            "DELETE FROM ai WHERE story_id IN (SELECT id FROM stories WHERE published<?1)",
            params![cutoff],
        )?;
        self.conn
            .execute("DELETE FROM stories WHERE published<?1", params![cutoff])?;
        Ok(())
    }

    // ---------- KEV ----------
    pub fn replace_kev(&self, entries: &[KevEntry]) -> rusqlite::Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM kev", [])?;
        {
            let mut st = tx.prepare(
                "INSERT OR REPLACE INTO kev(cve,vendor,product,name,date_added,description,ransomware) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            )?;
            for e in entries {
                st.execute(params![
                    e.cve,
                    e.vendor,
                    e.product,
                    e.name,
                    e.date_added,
                    e.description,
                    e.ransomware as i64
                ])?;
            }
        }
        tx.commit()
    }

    pub fn in_kev(&self, cve: &str) -> bool {
        self.conn
            .query_row("SELECT 1 FROM kev WHERE cve=?1", params![cve], |_| Ok(()))
            .optional()
            .ok()
            .flatten()
            .is_some()
    }

    pub fn kev_added_since(&self, date: &str) -> i64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM kev WHERE date_added>=?1",
                params![date],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    // ---------- KEV lookups ----------
    /// KEV entries added on or after `date` (YYYY-MM-DD).
    pub fn kev_recent(&self, date: &str) -> rusqlite::Result<Vec<KevRow>> {
        let mut st = self.conn.prepare(
            "SELECT cve,vendor,product,date_added,ransomware FROM kev WHERE date_added>=?1 LIMIT 3000",
        )?;
        let rows = st.query_map(params![date], |r| {
            Ok(KevRow {
                cve: r.get(0)?,
                vendor: r.get(1)?,
                product: r.get(2)?,
                date_added: r.get(3)?,
                ransomware: r.get::<_, i64>(4)? != 0,
            })
        })?;
        rows.collect()
    }

    // ---------- glossary ----------
    pub fn gloss_rows(&self) -> rusqlite::Result<Vec<GlossRow>> {
        let mut st = self.conn.prepare(
            "SELECT key,term,plain,analogy,status,origin,archived,added FROM gloss ORDER BY term COLLATE NOCASE",
        )?;
        let rows = st.query_map([], |r| {
            Ok(GlossRow {
                key: r.get(0)?,
                term: r.get(1)?,
                plain: r.get(2)?,
                analogy: r.get(3)?,
                status: r.get(4)?,
                origin: r.get(5)?,
                archived: r.get::<_, i64>(6)? != 0,
                added: r.get(7)?,
            })
        })?;
        rows.collect()
    }
    /// Number of AI-added terms still in play (not known, not archived).
    pub fn gloss_ai_active(&self) -> i64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM gloss WHERE origin='ai' AND archived=0 AND status!='known'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }
    pub fn gloss_has(&self, key: &str) -> bool {
        self.conn
            .query_row("SELECT 1 FROM gloss WHERE key=?1", params![key], |_| Ok(()))
            .optional()
            .ok()
            .flatten()
            .is_some()
    }
    pub fn gloss_insert(
        &self,
        key: &str,
        term: &str,
        plain: &str,
        analogy: &str,
        origin: &str,
        now: i64,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO gloss(key,term,plain,analogy,status,origin,archived,added) VALUES(?1,?2,?3,?4,'new',?5,0,?6)",
            params![key, term, plain, analogy, origin, now],
        )?;
        Ok(())
    }
    /// Set a term's status; built-in terms get a row on first change.
    pub fn gloss_set_status(
        &self,
        key: &str,
        term: &str,
        plain: &str,
        analogy: &str,
        status: &str,
        now: i64,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO gloss(key,term,plain,analogy,status,origin,archived,added) VALUES(?1,?2,?3,?4,?5,'builtin',0,?6)
             ON CONFLICT(key) DO UPDATE SET status=excluded.status, archived=0",
            params![key, term, plain, analogy, status, now],
        )?;
        Ok(())
    }
    pub fn gloss_expire(&self, now: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE gloss SET archived=1 WHERE origin='ai' AND status='new' AND archived=0 AND added<?1",
            params![now - 30 * DAY],
        )?;
        Ok(())
    }

    // ---------- CVSS (NVD) ----------
    pub fn cvss(&self, cve: &str) -> Option<(f64, String)> {
        self.conn
            .query_row(
                "SELECT score, severity FROM cvss WHERE cve=?1",
                params![cve],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .ok()
            .flatten()
    }
    pub fn has_cvss(&self, cve: &str) -> bool {
        self.cvss(cve).is_some()
    }
    pub fn set_cvss(
        &self,
        cve: &str,
        score: f64,
        severity: &str,
        now: i64,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO cvss(cve,score,severity,fetched) VALUES(?1,?2,?3,?4)",
            params![cve, score, severity, now],
        )?;
        Ok(())
    }

    // ---------- AI cache ----------
    pub fn ai_json(&self, story_id: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT json FROM ai WHERE story_id=?1",
                params![story_id],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }
    pub fn set_ai_json(
        &self,
        story_id: &str,
        value: &str,
        model: &str,
        now: i64,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO ai(story_id,json,model,created) VALUES(?1,?2,?3,?4)",
            params![story_id, value, model, now],
        )?;
        Ok(())
    }

    // ---------- full article text ----------
    pub fn article(&self, story_id: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT text FROM articles WHERE story_id=?1",
                params![story_id],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }
    pub fn set_article(&self, story_id: &str, text: &str, now: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO articles(story_id,text,fetched) VALUES(?1,?2,?3)",
            params![story_id, text, now],
        )?;
        Ok(())
    }

    // ---------- briefs & reading ----------
    pub fn brief_ids(&self, day: &str) -> Option<Vec<String>> {
        let s: Option<String> = self
            .conn
            .query_row("SELECT ids FROM briefs WHERE day=?1", params![day], |r| {
                r.get(0)
            })
            .optional()
            .ok()
            .flatten();
        s.and_then(|s| serde_json::from_str(&s).ok())
    }
    pub fn set_brief(&self, day: &str, ids: &[String]) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO briefs(day,ids) VALUES(?1,?2)",
            params![day, json(ids)],
        )?;
        Ok(())
    }
    pub fn mark_read(&self, day: &str, story_id: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO reads(day,story_id) VALUES(?1,?2)",
            params![day, story_id],
        )?;
        Ok(())
    }
    pub fn read_ids(&self, day: &str) -> rusqlite::Result<Vec<String>> {
        let mut st = self
            .conn
            .prepare("SELECT story_id FROM reads WHERE day=?1")?;
        let rows = st.query_map(params![day], |r| r.get(0))?;
        rows.collect()
    }
    pub fn read_days(&self) -> rusqlite::Result<Vec<String>> {
        let mut st = self
            .conn
            .prepare("SELECT DISTINCT day FROM reads ORDER BY day DESC LIMIT 400")?;
        let rows = st.query_map([], |r| r.get(0))?;
        rows.collect()
    }

    // ---------- ideas / backlog ----------
    pub fn active_idea_count(&self) -> i64 {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM ideas WHERE status='active'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0)
    }

    /// Adds an idea if the backlog has room and the same idea isn't already
    /// active or recently dismissed. Returns true if added.
    pub fn add_idea(
        &self,
        title: &str,
        detail: &str,
        theme: &str,
        story_id: Option<&str>,
        now: i64,
    ) -> rusqlite::Result<bool> {
        if self.active_idea_count() >= BACKLOG_CAP {
            return Ok(false);
        }
        let exists: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM ideas WHERE title=?1 AND (status='active' OR created>?2)",
                params![title, now - 14 * DAY],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if exists {
            return Ok(false);
        }
        self.conn.execute(
            "INSERT INTO ideas(title,detail,theme,story_id,created) VALUES(?1,?2,?3,?4,?5)",
            params![title, detail, theme, story_id, now],
        )?;
        Ok(true)
    }

    pub fn expire_ideas(&self, now: i64) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE ideas SET status='archived', reason='expired' WHERE status='active' AND starred=0 AND created<?1",
            params![now - IDEA_EXPIRY_DAYS * DAY],
        )
    }

    pub fn ideas(&self, status: &str, now: i64) -> rusqlite::Result<Vec<Idea>> {
        let mut st = self.conn.prepare(
            "SELECT id,title,detail,theme,created,starred,status,reason FROM ideas WHERE status=?1 ORDER BY starred DESC, created DESC LIMIT 200",
        )?;
        let rows = st.query_map(params![status], |r| {
            let created: i64 = r.get(4)?;
            let starred: bool = r.get::<_, i64>(5)? != 0;
            let status: String = r.get(6)?;
            let expires = if status == "active" && !starred {
                Some(((created + IDEA_EXPIRY_DAYS * DAY - now) / DAY).max(0))
            } else {
                None
            };
            Ok(Idea {
                id: r.get(0)?,
                title: r.get(1)?,
                detail: r.get(2)?,
                theme: r.get(3)?,
                created,
                starred,
                status,
                reason: r.get(7)?,
                expires_in_days: expires,
            })
        })?;
        rows.collect()
    }

    pub fn set_idea_starred(&self, id: i64, starred: bool) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE ideas SET starred=?2 WHERE id=?1 AND status='active'",
            params![id, starred as i64],
        )
    }
    pub fn dismiss_idea(&self, id: i64) -> rusqlite::Result<usize> {
        self.conn.execute("UPDATE ideas SET status='archived', reason='dismissed', starred=0 WHERE id=?1 AND status='active'", params![id])
    }
    pub fn restore_idea(&self, id: i64, now: i64) -> rusqlite::Result<usize> {
        if self.active_idea_count() >= BACKLOG_CAP {
            return Ok(0);
        }
        self.conn.execute("UPDATE ideas SET status='active', reason=NULL, created=?2 WHERE id=?1 AND status='archived'", params![id, now])
    }
    pub fn delete_idea(&self, id: i64) -> rusqlite::Result<usize> {
        self.conn.execute(
            "DELETE FROM ideas WHERE id=?1 AND status='archived'",
            params![id],
        )
    }

    // ---------- projects ----------
    pub fn project(&self, week: &str) -> rusqlite::Result<Option<ProjectRow>> {
        self.conn
            .query_row(
                "SELECT plan,done,completed,completed_at FROM projects WHERE week=?1",
                params![week],
                |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0, r.get(3)?)),
            )
            .optional()
    }
    pub fn set_project(&self, week: &str, plan: &str, done: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO projects(week,plan,done) VALUES(?1,?2,?3)",
            params![week, plan, done],
        )?;
        Ok(())
    }
    pub fn update_project_done(&self, week: &str, done: &str) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE projects SET done=?2 WHERE week=?1",
            params![week, done],
        )
    }
    pub fn complete_project(
        &self,
        week: &str,
        completed: bool,
        now: i64,
    ) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE projects SET completed=?2, completed_at=?3 WHERE week=?1",
            params![
                week,
                completed as i64,
                if completed { Some(now) } else { None }
            ],
        )
    }
    pub fn completed_projects(&self) -> rusqlite::Result<Vec<(String, String, i64)>> {
        let mut st = self.conn.prepare(
            "SELECT week,plan,completed_at FROM projects WHERE completed=1 ORDER BY completed_at DESC LIMIT 200",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get::<_, Option<i64>>(2)?.unwrap_or(0),
            ))
        })?;
        rows.collect()
    }

    // ---------- watchlist ----------
    pub fn watchlist(&self) -> rusqlite::Result<Vec<String>> {
        let mut st = self
            .conn
            .prepare("SELECT term FROM watchlist ORDER BY term")?;
        let rows = st.query_map([], |r| r.get(0))?;
        rows.collect()
    }
    pub fn add_watch(&self, term: &str) -> rusqlite::Result<usize> {
        self.conn.execute(
            "INSERT OR IGNORE INTO watchlist(term) VALUES(?1)",
            params![term],
        )
    }
    pub fn remove_watch(&self, term: &str) -> rusqlite::Result<usize> {
        self.conn
            .execute("DELETE FROM watchlist WHERE term=?1", params![term])
    }

    // ---------- quiz ----------
    pub fn quiz(&self, day: &str) -> rusqlite::Result<Option<QuizRow>> {
        self.conn
            .query_row(
                "SELECT term,options,answer,chosen FROM quiz WHERE day=?1",
                params![day],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
    }
    pub fn set_quiz(
        &self,
        day: &str,
        term: &str,
        options: &str,
        answer: i64,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO quiz(day,term,options,answer) VALUES(?1,?2,?3,?4)",
            params![day, term, options, answer],
        )?;
        Ok(())
    }
    pub fn answer_quiz(&self, day: &str, chosen: i64) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE quiz SET chosen=?2 WHERE day=?1 AND chosen IS NULL",
            params![day, chosen],
        )
    }
    pub fn missed_terms(&self, limit: i64) -> rusqlite::Result<Vec<String>> {
        let mut st = self.conn.prepare(
            "SELECT term FROM quiz WHERE chosen IS NOT NULL AND chosen<>answer ORDER BY day DESC LIMIT ?1",
        )?;
        let rows = st.query_map(params![limit], |r| r.get(0))?;
        rows.collect()
    }
}

fn row_to_story(r: &rusqlite::Row) -> rusqlite::Result<StoryRow> {
    let sources: String = r.get(5)?;
    let cves: String = r.get(6)?;
    Ok(StoryRow {
        id: r.get(0)?,
        title: r.get(1)?,
        link: r.get(2)?,
        summary: r.get(3)?,
        published: r.get(4)?,
        sources: serde_json::from_str(&sources).unwrap_or_default(),
        cves: serde_json::from_str(&cves).unwrap_or_default(),
        uk: r.get::<_, i64>(7)? != 0,
    })
}

fn json<T: serde::Serialize + ?Sized>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "[]".into())
}

pub fn story_id(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    hex::encode(&h.finalize()[..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(title: &str, link: Option<&str>, src: &str) -> RawItem {
        RawItem {
            title: title.into(),
            link: link.map(Into::into),
            summary: "s".into(),
            published: 1000,
            source_id: src.into(),
            source_name: src.into(),
            cves: vec![],
        }
    }

    #[test]
    fn dedupes_across_sources() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_items(
            &[item(
                "Fortinet warns of FortiGate zero-day exploited in attacks",
                Some("https://a.example/1"),
                "A",
            )],
            1000,
        )
        .unwrap();
        s.upsert_items(
            &[item(
                "FortiGate zero-day exploited in attacks, Fortinet warns",
                Some("https://b.example/2"),
                "B",
            )],
            1000,
        )
        .unwrap();
        let all = s.stories_since(0).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].sources, vec!["A", "B"]);
    }

    #[test]
    fn sql_injection_strings_are_inert() {
        let s = Store::open_in_memory().unwrap();
        let evil = "x'); DROP TABLE stories; --";
        s.upsert_items(&[item(evil, None, evil)], 1000).unwrap();
        s.add_watch(evil).unwrap();
        s.set_setting(evil, evil).unwrap();
        assert_eq!(s.stories_since(0).unwrap()[0].title, evil);
        assert_eq!(s.watchlist().unwrap(), vec![evil.to_string()]);
        assert_eq!(s.setting(evil).as_deref(), Some(evil));
    }

    #[test]
    fn backlog_cap_and_expiry() {
        let s = Store::open_in_memory().unwrap();
        for i in 0..15 {
            s.add_idea(&format!("idea {i}"), "d", "t", None, 0).unwrap();
        }
        assert_eq!(s.active_idea_count(), BACKLOG_CAP);
        let first = s.ideas("active", 0).unwrap();
        s.set_idea_starred(first[0].id, true).unwrap();
        let expired = s.expire_ideas(IDEA_EXPIRY_DAYS * DAY + 10).unwrap();
        assert_eq!(expired, (BACKLOG_CAP - 1) as usize);
        assert_eq!(s.active_idea_count(), 1); // the starred one survives
    }

    #[test]
    fn dismiss_restore_delete() {
        let s = Store::open_in_memory().unwrap();
        s.add_idea("a", "d", "t", None, 0).unwrap();
        let id = s.ideas("active", 0).unwrap()[0].id;
        assert_eq!(
            s.delete_idea(id).unwrap(),
            0,
            "active ideas must be dismissed before delete"
        );
        s.dismiss_idea(id).unwrap();
        assert_eq!(s.ideas("archived", 0).unwrap().len(), 1);
        s.restore_idea(id, 5).unwrap();
        assert_eq!(s.active_idea_count(), 1);
        s.dismiss_idea(id).unwrap();
        assert_eq!(s.delete_idea(id).unwrap(), 1);
        assert!(s.ideas("archived", 0).unwrap().is_empty());
    }

    #[test]
    fn duplicate_ideas_skipped() {
        let s = Store::open_in_memory().unwrap();
        assert!(s.add_idea("same", "d", "t", None, 0).unwrap());
        assert!(!s.add_idea("same", "d", "t", None, 10).unwrap());
    }
}
