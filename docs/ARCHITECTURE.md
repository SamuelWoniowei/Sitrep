# Architecture

Sitrep is a [Tauri 2](https://v2.tauri.app) desktop app: a Rust backend that does all the real work, and a small React + TypeScript UI rendered in the system webview (WebView2 on Windows).

```
┌──────────────────────────── Sitrep process ────────────────────────────┐
│                                                                        │
│  Webview (React UI)                    Rust backend                    │
│  ─────────────────                     ────────────                    │
│  • Renders text only        invoke()   commands.rs  (validates input)  │
│  • No network, fs, shell  ───────────▶   │                             │
│  • CSP: self only                        ├─ core.rs   brief, backlog,  │
│                                          │            project, quiz,   │
│                                          │            recap, radar     │
│                                          ├─ store.rs  SQLite ──────────┼──▶ data.sqlite3
│                                          ├─ feeds.rs  parse + clean    │    (user profile)
│                                          ├─ net.rs ───────────────────┼──▶ 6 HTTPS feeds
│                                          └─ ai.rs ────────────────────┼──▶ Ollama 127.0.0.1
└────────────────────────────────────────────────────────────────────────┘
```

## Data flow

1. **Refresh** (on launch, every 30 minutes while open, or manually): `net.rs` fetches the six sources in parallel. `feeds.rs` parses RSS/Atom and the CISA KEV JSON, converting everything to bounded plain text.
2. **Store**: `store.rs` merges near-duplicate headlines across sources (token similarity ≥ 0.6, within 4 days) and records which sources covered each story. Stories older than 90 days are pruned.
3. **Brief**: `core.rs` scores recent stories:
   - +50 exploited now (CVE on CISA KEV, or "zero-day"/"actively exploited")
   - +30 major incident (ransomware, breach…)
   - +20 UK
   - +25 watchlist match
   - +10 per extra source
   - −0.5 per hour of age

   It picks 3, with at most 2 per category, and includes a UK story when one exists. The brief is fixed for the day once chosen.
4. **Ideas**: each brief story with a clear technical theme adds one lab idea to the backlog (cap 10, 21-day expiry unless starred).
5. **AI (optional)**: the UI asks the backend to enhance each brief story. The backend calls the local Ollama model, validates the JSON reply and caches it. Without AI, the source summary, built-in glossary and templates are used.
6. **Project of the week**: the dominant theme in the past 7 days selects a project template. It is locked in once there's enough news (5+ stories) or as soon as the user ticks a step.

## Why these choices

- **Tauri over Electron**: a far smaller installer, Rust for the parsing of untrusted input, and a capability system that denies the UI everything by default.
- **Rust owns all I/O**: the webview is the most exposed component, so it gets no network or file access at all.
- **Plain text everywhere**: removing HTML at the boundary is simpler and safer than trying to sanitise it for display.
- **Local AI only, optional**: free, private, and the app is fully useful without it.
- **Deterministic ranking**: the AI never decides what you see, only how it's explained.

## Key files

| File | Responsibility |
|---|---|
| `src-tauri/src/net.rs` | Source list, HTTPS allowlist, redirect policy, size caps, link validation |
| `src-tauri/src/feeds.rs` | Feed and KEV parsing, CVE extraction |
| `src-tauri/src/text.rs` | HTML → text, control/bidi stripping, truncation, title similarity |
| `src-tauri/src/store.rs` | Schema and all queries |
| `src-tauri/src/core.rs` | Ranking, brief, quiz, project, recap, radar, streak |
| `src-tauri/src/ai.rs` | Ollama client, prompt fencing, output validation |
| `src-tauri/src/commands.rs` | Every command the UI can call |
| `src-tauri/tauri.conf.json` | Window, CSP, bundle settings |
| `src-tauri/capabilities/default.json` | UI permissions (core only) |
| `src/App.tsx` | Layout, navigation, refresh, listen mode |
| `src/Today.tsx`, `src/StoryCard.tsx` | Home screen |
| `src/pages.tsx` | Project, Backlog, Built, Recap, Radar, Glossary, Watchlist, Settings |

## Adding a news source

1. Add it to `SOURCES` in `net.rs`. Use HTTPS, and add any redirect host to `EXTRA_ALLOWED_HOSTS`.
2. Run `cargo test`: the allowlist test checks every source is fetchable.
3. Update the source list in `docs/THREAT_MODEL.md` and the README.
