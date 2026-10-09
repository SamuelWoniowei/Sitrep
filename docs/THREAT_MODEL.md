# Threat model

Sitrep is a single-user desktop app. It downloads public news feeds, stores them locally and optionally summarises them with a local AI model. This document lists what it protects, where untrusted data enters, and how each threat is handled.

## Assets

| Asset | Why it matters |
|---|---|
| The user's computer | A news reader must never become a way to run code, read files or reach the local network. |
| Reading history, watchlist, backlog and projects | Personal data that shows interests and job-search focus. It should never leave the machine. |
| Integrity of what the user reads | A tampered or injected summary could mislead the user, e.g. "this flaw is harmless, no need to patch". |

## Trust boundaries

```
 Internet feeds (untrusted) ──HTTPS, allowlist──▶ Rust backend ──plain text──▶ SQLite (local)
                                                    │   ▲
              Ollama on 127.0.0.1 (semi-trusted) ◀──┘   │ validated commands only
                                                        │
                                          Webview UI (untrusted renderer, CSP-locked)
```

1. **Feeds → backend.** Everything in a feed (titles, descriptions, links, dates, XML structure) is attacker-controllable, whether by a compromised source, a malicious advertiser in a feed, or a hostile redirect.
2. **AI model → backend.** The model processes untrusted article text, so its output is treated as untrusted too.
3. **UI → backend.** The webview is treated as untrusted. If it were ever compromised, the backend must still refuse dangerous actions.

## Threats and mitigations

| # | Threat | Mitigation | Where |
|---|---|---|---|
| T1 | **XSS / script injection** via HTML in feed titles or summaries | All feed text is parsed and reduced to plain text, dropping `script`, `style`, `iframe`, `svg` and similar elements. The UI renders text nodes only, with no `dangerouslySetInnerHTML` (enforced by a test). The CSP allows scripts only from the app bundle. | `text.rs`, `security.test.tsx`, `tauri.conf.json` |
| T2 | **XML attacks**: XXE (reading local files) and "billion laughs" (memory exhaustion) | The parser (feed-rs on quick-xml) does not resolve external entities or expand custom DTD entities. Both attacks are covered by tests. | `feeds.rs` tests |
| T3 | **Resource exhaustion** from huge or endless feeds | 5 MB cap enforced while streaming (a lying `Content-Length` is rejected), 25 s timeout, 100 items per feed, per-field length caps. | `net.rs`, `feeds.rs` |
| T4 | **SSRF / unexpected destinations** via redirects | HTTPS only, fixed host allowlist, port 443 only, no credentials in URLs, at most 3 redirects and only to allowlisted HTTPS hosts. The final URL is re-checked. | `net.rs` |
| T5 | **Malicious links** (`javascript:`, `file:`, `ms-msdt:`, `smb:`, raw IPs, localhost) | Links are validated on import and again at click time: only `https://` to a real domain name. The UI never handles a URL; it asks the backend to open "story X". | `net.rs::openable`, `commands.rs::open_story` |
| T6 | **Prompt injection** in an article ("ignore previous instructions…") | Article text is wrapped in random per-request markers that the article cannot forge. The system prompt tells the model to treat it as data. The model has **no tools**, so injection cannot cause actions. Output must be strict JSON, is stripped to plain text and length-capped, and AI summaries are labelled as such. | `ai.rs` |
| T7 | **Misleading AI summary** (hallucination or successful injection) | Residual risk. Every story has a "Read source" link, AI summaries are labelled, and the brief's ranking never depends on AI output. | UI, `core.rs` |
| T8 | **SQL injection** | Every query is parameterised. Tests insert classic injection strings through every write path. | `store.rs` |
| T9 | **Compromised webview abusing the backend** | Least-privilege Tauri capabilities: no filesystem, shell, HTTP or opener permissions for the UI. Every command validates its inputs (story IDs must be 24 hex chars; watchlist terms use a strict character set; question length is limited). | `capabilities/default.json`, `commands.rs` |
| T10 | **Data leaving the machine** | No telemetry or analytics code. The UI's CSP blocks all network access except to the backend. Only the six feed URLs, full articles on the five allowlisted news hosts (if enabled), and `127.0.0.1:11434` are ever contacted. No referrer is sent. | `net.rs`, CSP |
| T11 | **Local AI endpoint abuse** (redirects, oversized replies) | The AI client never follows redirects, ignores proxies, caps replies at 512 KB, and only uses a model name reported by the local Ollama install. | `net.rs`, `ai.rs` |
| T12 | **Text spoofing** with bidi-override or zero-width characters | Stripped from all stored and displayed text. | `text.rs` |
| T13 | **Hammering sources / getting blocked** | At most one fetch attempt per 2 minutes; automatic refresh at most hourly. | `commands.rs::refresh` |
| T14 | **Vulnerable dependencies** | `cargo audit` and `npm audit` run in CI; Dependabot opens update PRs. | `.github/` |
| T16 | **Full-article fetch reaching arbitrary sites** (a feed links to an attacker's page, or a redirect does) | Full text is fetched only for the day's 3 brief stories, only from five exact hosts (the news sites whose feeds are read), HTTPS on port 443, redirects only within those hosts, HTML content type only, 2 MB cap, no cookies, no JavaScript executed. The page is reduced to plain-text paragraphs (max 6,000 chars) before the AI sees it. Can be switched off in Settings. | `net.rs::article_fetchable`, `text.rs::extract_article` |
| T17 | **Data leaving via Ollama cloud models** (Ollama can proxy `:cloud` models to its servers) | Any model whose name mentions "cloud" is filtered from the model list, rejected in Settings, and refused at generation time, so article text and questions never leave the machine. | `ai.rs::is_cloud_model`, `commands.rs` |
| T15 | **Tampered installer** | Built reproducibly by GitHub Actions from the tagged source. *Not yet code-signed*: see residual risks. | `.github/workflows/release.yml` |

## Residual risks (accepted, for now)

- **Unsigned installer.** Windows SmartScreen will warn. Users should download only from this repository's Releases page. Code signing is on the roadmap.
- **AI accuracy.** A local model can be wrong. Summaries are a convenience, not a source of truth.
- **Local database is not encrypted.** It sits in the user's profile, protected by the OS account. It contains no secrets, only news and the user's study notes.
- **Ollama itself** is a separate application outside Sitrep's control. Sitrep only talks to it on localhost and treats its output as untrusted.
- **Feed sources** could publish misleading content. Sitrep shows the source and links to the original.

## Changing security-relevant code

Changes to any of the following need an update to this document and the tests:
the `SOURCES` or `ARTICLE_HOSTS` lists in `net.rs`, the cloud-model rule in `ai.rs`, the CSP in `tauri.conf.json`, `capabilities/`, any new Tauri command, or any change to how text is rendered in the UI.
