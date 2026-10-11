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
| T18 | **Malicious update** (tampered download, hijacked release, downgrade to an old vulnerable build) | Updates are checked **only when the user clicks** "Check for updates". The single endpoint is this repo's GitHub Releases over HTTPS, fixed in `tauri.conf.json`. Every update must carry a valid signature from the project's private key; the public key is compiled in and unsigned or wrongly signed files are refused. Only strictly newer versions install. The UI has no updater permission and can't change the source. Config guardrail tests fail the build if any of this is weakened. | `updates.rs`, `tauri.conf.json` |
| T19 | **Build pipeline / GitHub account compromise** (stolen signing key, malicious workflow change, hijacked third-party Action) | Signing key stored as a GitHub secret (encrypted, write-only, masked, never given to fork or Dependabot PRs), intended to be scoped to the `release` environment with the owner as required reviewer. The release workflow runs only manually and produces a **draft** the owner must publish. All Actions are pinned to full commit SHAs; checkout doesn't persist credentials; CI has read-only permissions and no secrets. The owner's GitHub account should use 2FA/passkeys. | `.github/workflows/` |
| T15 | **Tampered installer** | Built reproducibly by GitHub Actions from the tagged source. *Not yet code-signed*: see residual risks. | `.github/workflows/release.yml` |
| T20 | **Voice download tampering** (hijacked GitHub/Hugging Face file, bad redirect, malicious zip) | One-time, user-triggered download of Piper (official GitHub release) and the Alan voice (official Hugging Face file). Both are pinned to an exact SHA-256 and size cap; a mismatch discards the file. Redirects only to GitHub/Hugging Face hosts over HTTPS. The zip is unpacked with path-escape, symlink, file-count and size checks. The voice config is built into the app, not downloaded. Before every use the Piper program, its libraries and the model are re-hashed against pinned values. | `voice.rs` |
| T21 | **Text injection into the voice engine** | Text goes to Piper on standard input only, never on a command line; the program is started directly (no shell), with control characters stripped, 8,000-character cap, 120 s timeout and a 60 MB output cap. | `voice.rs::synth` |
| T22 | **Speech text leaving the PC** (Windows "Online (Natural)" voices send text to Microsoft) | System voices are limited to ones that run on the device; names containing "online", "natural" or "cloud" and non-local voices are never used. | `listen.ts::pickLocalVoice` |
| T23 | **CVE severity lookups leaking or being abused** | One extra host (`services.nvd.nist.gov`). Only a validated CVE ID is sent (strict `CVE-YYYY-N+` pattern, checked before building the URL); responses are capped at 1 MB and reduced to a score (0 to 10) and a fixed severity label. At most 5 lookups per refresh, 7 seconds apart. Failures are silently skipped. | `net.rs::fetch_cvss`, `commands.rs::refresh` |
| T24 | **More feeds widen the attack surface** | CISA Advisories, Microsoft MSRC, Cisco Talos and Krebs on Security are fixed HTTPS feeds under the same rules as the originals (allowlist, port 443, size/time limits, text sanitising). Full-article fetch adds only `www.cisa.gov`, `krebsonsecurity.com`, `blog.talosintelligence.com`. | `net.rs` |
| T25 | **"Am I affected?" reading too much** | It reads only the names of installed programs (Windows uninstall registry keys via the system `reg.exe`), keeps nothing, sends nothing, and the UI cannot read the registry itself. | `intel.rs::installed_programs` |
| T26 | **Lab pack writing unsafe or malicious rules** | Indicators are extracted by regex from untrusted article text, then restricted to strict character sets before being placed in any rule or CSV; lists are capped at 40 per type; private/reserved IPs and known-benign domains are skipped. Files are written to a fixed folder under Documents, named by date and story ID. Rules are labelled DRAFT / lab use only. | `intel.rs::extract_iocs`, `lab_pack_files` |
| T27 | **Glossary / actor data being poisoned by AI output** | AI-added terms are plain-text, length-capped, deduplicated against built-in terms, capped at 15 active, and expire after 30 days. Actor profiles are built into the app, not generated. | `intel.rs` |
| T28 | **Weekly digest page used for script injection or tracking** | The exported HTML escapes all feed-derived text, carries a CSP meta tag that blocks scripts and remote loads, and includes only https links. A plain-text copy is also written. | `digest.rs` |
| T29 | **Log hunt reading or leaking sensitive files** | The scan is local and read-only, started from a native file dialog opened by Rust only. Caps: 4 GB, 120 s, 64 KB per line, 200 hits. Matches are sanitised and shortened. Nothing from the file is sent over the network. The UI has no file-system or dialog permission. | `hunt.rs`, `commands.rs` |
| T30 | **Dialog plugin widening the attack surface** | `tauri-plugin-dialog` is used from Rust only. No dialog capability is granted to the webview. | `lib.rs`, capabilities |
| T31 | **AI-written fun facts being wrong or carrying injected content** | The facts prompt contains no article or web text, only the app's own instructions and earlier saved facts. Output must be JSON, is reduced to plain text, capped at 220 characters, rejected if it has links or `@`, de-duplicated, and capped at 60 saved. The UI labels these as AI-written and renders them as text. The daily fact is always from the built-in list. | `ai.rs::validate_facts`, `commands.rs::make_facts` |
| T32 | **Prompt injection through the SOC shift chat or notes** | Characters and their knowledge are built into the app. The UI only sends a person's id and what the analyst typed; unknown ids are refused. Typed text is fenced with random markers and the model is told it is untrusted. Replies must be JSON, are reduced to plain text, capped at 500 characters, and rejected if they contain links or `@`. Only the last 12 turns, 300 characters each, are used. The model has no tools, so the worst case is an odd reply in a training exercise. | `ai.rs::persona_prompt`, `validate_reply`, `commands.rs::shift_chat` |
| T33 | **Handover-note feedback being wrong or leaking** | The note is fenced as untrusted; the facts are built-in text. Output is validated JSON, plain text, capped (3 strengths, 4 gaps, one tip). It is advice only and never changes the score. The note and facts go only to the local Ollama on 127.0.0.1; cloud models stay blocked. | `ai.rs::note_prompt`, `validate_note_feedback`, `commands.rs::shift_feedback` |
| T34 | **Writing arbitrary data through the shift score store** | `save_shift_result` accepts only known shift ids and sane score ranges, and stores a small fixed struct. Nothing the UI sends is stored as free text. | `commands.rs::save_shift_result` |
| T35 | **AI summaries claiming to be based on the full article when they are not** | The "basis" label is set by Sitrep from the length of the text actually read, never taken from the model's output (a forged value is cleared). | `ai.rs::validate_summary`, `commands.rs::enhance_story` |

## Residual risks (accepted, for now)

- **Signing key on GitHub.** Accepted for a single-user app; mitigated by environment scoping, required review, drafts and 2FA. The stronger alternative (offline key, local release builds) is documented here if needs change.
- **Unsigned installer.** Windows SmartScreen will warn. Users should download only from this repository's Releases page. Code signing is on the roadmap.
- **AI accuracy.** A local model can be wrong. Summaries are a convenience, not a source of truth.
- **Local database is not encrypted.** It sits in the user's profile, protected by the OS account. It contains no secrets, only news and the user's study notes.
- **Ollama itself** is a separate application outside Sitrep's control. Sitrep only talks to it on localhost and treats its output as untrusted.
- **Piper's voice engine** is third-party native code run on your PC. It is pinned by hash and given only text, but its internals are not audited by this project.
- **Globe and "Am I affected?" are indicative.** The globe shows what news names together, not confirmed attacks; the installed-programs check cannot compare version numbers.
- **Feed sources** could publish misleading content. Sitrep shows the source and links to the original.

## Changing security-relevant code

Changes to any of the following need an update to this document and the tests:
the `SOURCES`, `ARTICLE_HOSTS` or `NVD_HOST` in `net.rs`, the pinned URLs and hashes in `voice.rs`, the cloud-model rule in `ai.rs`, the CSP in `tauri.conf.json`, `capabilities/`, any new Tauri command, or any change to how text is rendered in the UI.
