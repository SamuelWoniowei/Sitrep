# Sitrep

**A calm, private daily cybersecurity brief for your desktop.**

Sitrep reads the main security news sources for you and gives you **three stories a day** in plain English, each with a two-sentence TL;DR and a line on why it matters to you. Around that sits a small learning loop: a term of the day, one quiz question, a weekly lab project built from the week's news, and an idea backlog that cleans itself up.

It's built for people who want to keep up with security without drowning in it, and who would rather spend the time building things in a home lab.

![Sitrep home screen (sample data)](docs/screenshot.png)

## Features

- **A calm daily brief:** at most three stories a day, ranked by what is being exploited, big incidents, UK relevance and your watchlist.
- **Fuller summaries:** a 4 to 5 sentence summary (what happened, the weakness, how it worked, impact and fix), a "plain words" version with an analogy, what to do, and notes for the career roles you pick. All written by a local AI (Ollama); nothing leaves your PC.
- **Simple and Deeper views:** step-by-step storyboard and technical detail on demand.
- **Smart glossary:** New / Learning / Known, merges duplicates, caps AI-added terms at 15 and tidies old ones away.
- **Developing stories:** related earlier coverage linked under each story.
- **Intel:** threat-actor profiles, and "Am I affected?" (matches your installed programs against recently exploited flaws; read-only).
- **Lab pack:** export draft Suricata rules, Wazuh lists/rules and an IOC CSV for the story, for your home lab.
- **Live Ops:** interactive globe of countries in the news, flaw lifecycle tracker, groups-and-flaws map, 12-week reading calendar.
- **Natural British voice (optional):** Piper "Alan", one verified download, then offline. Listen mode never uses online voices.
- **Weekly project, idea backlog, quiz, recap, skills radar** (from v0.1).
- **Motion on/off** and automatic reduced-motion support.
- **Sources:** BleepingComputer, The Record, The Hacker News, NCSC UK, SANS ISC, CISA Advisories, Microsoft MSRC, Cisco Talos, Krebs on Security, CISA KEV, plus NVD severity scores.

## Privacy

- **No account, no analytics, no telemetry, no tracking.**
- Your reading history, backlog, projects and watchlist are stored in a local SQLite database in your user profile.
- The only internet traffic is downloading six public feeds over HTTPS and, for the 3 daily stories, the full article from those same news sites (switchable in Settings). Both lists are in [`src-tauri/src/net.rs`](src-tauri/src/net.rs).
- The optional AI runs **on your own machine** through [Ollama](https://ollama.com). Ollama "cloud" models are blocked, so article text is never sent to a cloud AI.
- System fonts only, so no requests to font CDNs.

## Security

Sitrep treats every feed and every AI response as hostile input. In short:

- The UI has **no network, filesystem or shell access**. A strict Content Security Policy only lets it talk to the app's own Rust backend.
- All feed content is converted to **plain text** before storage, and the UI never renders HTML.
- Feeds are fetched over **HTTPS only**, from a **fixed allowlist**, with size and time limits and no cookies.
- Full articles are fetched only from the five news sites Sitrep already reads, and reduced to plain text before the AI sees them.
- Article links open only if they are plain `https://` links to a real domain.
- AI prompts **fence untrusted article text** behind random per-request markers, and AI output is validated as strict JSON and stripped to plain text.
- All database queries are parameterised.

Details: [threat model](docs/THREAT_MODEL.md), [security testing](docs/SECURITY_TESTING.md), [reporting a vulnerability](SECURITY.md).

## Install (Windows)

1. Go to [Releases](../../releases) and download the latest `Sitrep_x.y.z_x64-setup.exe`, and check its hash against `SHA256SUMS.txt` with `Get-FileHash`.
2. Run it. Windows SmartScreen may warn that the app is unrecognised, because the installer isn't code-signed yet. Choose **More info → Run anyway**.
3. Open Sitrep from the Start menu. It fetches the news on first launch.

### Optional: local AI for better summaries

Sitrep works without AI and uses each source's own summary. For plain-English rewrites, the Deeper view and Ask:

1. Install Ollama from [ollama.com](https://ollama.com).
2. Run `ollama pull llama3.2:3b` in a terminal (about 2 GB, one time).
3. Restart Sitrep, or click **Settings → Check again**.

A machine with 8 GB+ RAM is recommended. Larger models give better summaries if your PC can run them, and you can pick one in Settings: `llama3.1:8b`, `qwen3:8b`, or on 32 GB RAM `qwen3:30b-a3b` (fast for its quality). Sitrep turns off Qwen 3's slow "thinking" mode automatically. Models tagged `cloud` are always blocked.

## Updates

Sitrep never checks for updates on its own. When you want to update, open **Settings → Check for updates**. Updates come only from this repository's GitHub Releases and must carry a valid signature from the project's signing key, or they are refused.

For maintainers, releasing a new version:
1. Bump the version in `package.json`, `src-tauri/Cargo.toml` and `src-tauri/tauri.conf.json`, then push.
2. Actions → **Release** → Run workflow. It runs the tests, builds, signs and creates a **draft** release with `SHA256SUMS.txt`.
3. Review the draft and click **Publish**. Only published releases are offered to the app.

## Build from source

Requirements: [Node.js 20+](https://nodejs.org), [Rust (stable)](https://rustup.rs), and the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for your OS (on Windows: Microsoft C++ Build Tools and WebView2, which is preinstalled on Windows 10/11).

```bash
npm ci
npm run tauri dev        # run in development
npm run tauri build      # build the installer (src-tauri/target/release/bundle)
```

Tests and checks:

```bash
npm test                                  # UI tests, including XSS and code guardrails
cd src-tauri && cargo test                # backend tests, including attack cases
cargo clippy --all-targets -- -D warnings
cargo audit && npm audit
```

## Project layout

```
src/                 React + TypeScript UI (renders text only; no network access)
src-tauri/src/
  net.rs             The only network code: HTTPS allowlist, limits, link checks
  feeds.rs           RSS/Atom and CISA KEV parsing into bounded plain text
  text.rs            HTML stripping, control-character removal, truncation
  store.rs           SQLite storage (parameterised queries only)
  core.rs            Brief ranking, backlog, projects, quiz, recap, radar
  ai.rs              Local Ollama client, prompt fencing, output validation
  commands.rs        The UI ↔ backend bridge, with input validation
  glossary.rs        Built-in plain-English glossary
  themes.rs          Story categories, lab ideas and weekly project templates
docs/                Architecture, threat model, security testing
```

More detail is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Roadmap

- macOS build
- Code-signed Windows installer (SignPath for open source)
- System tray and a morning notification
- Optional cloud AI (bring your own key, stored in the OS keychain)
- Export a finished project as a GitHub-ready write-up

## Credits

News comes from BleepingComputer, The Record, The Hacker News, the UK NCSC, the SANS Internet Storm Center and the CISA Known Exploited Vulnerabilities catalogue. Sitrep links to the original articles and doesn't republish them.

## License

[MIT](LICENSE) © 2026 Samuel Woniowei

## v0.3.0 additions

- Separate pages for **Developing** (day-by-day timelines with "new since you read"), **Threat actors** (what they want, how they operate), **Am I affected?**, **Lab pack** (weekly) and **Sunday Sitrep**.
- **Watchlist board** with 30-day counts and a 14-day sparkline per term; **Systems** page; "LIVE · N SOURCES" indicator; greeting by name (Settings → You); 16-week reading calendar.
- "How the attack worked" strip on each story (estimated from the story's own words).
- All new data is computed locally from the stored stories; no new network access.

## v0.4.0 additions

- **Weekly digest**: export a shareable HTML + text summary of the week (Sunday Sitrep page). Escaped, script-free, https links only.
- **Attack replay**: step through a developing story as an animated attack timeline.
- **Log hunt**: pick a local log file and scan it, read-only, against indicators from the last 30 days of stories. Nothing leaves your PC.
