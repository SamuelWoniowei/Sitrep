import { useEffect, useState } from 'react'
import { api, errText, type AiStatus, type UpdateInfo, type BuiltItem, type Idea, type Project, type RadarRow, type Recap, type Term } from './api'

function useLoad<T>(fn: () => Promise<T>): [T | null, (v: T) => void, string | null, () => void] {
  const [data, setData] = useState<T | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const load = () => { fn().then(setData).catch((e) => setErr(errText(e))) }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(load, [])
  return [data, setData, err, load]
}

const fmtDate = (ts: number) => new Date(ts * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })

export function ProjectPage() {
  const [p, setP, err] = useLoad<Project | null>(api.project)
  const [e2, setE2] = useState<string | null>(null)
  if (err) return <div className="error">{err}</div>
  if (!p) return <div className="muted">Loading…</div>
  const run = (fn: () => Promise<Project | null>) => fn().then(setP).catch((e) => setE2(errText(e)))
  const allDone = p.done.every(Boolean)
  return (
    <section className="panel page">
      <div className="mono small accent">PROJECT OF THE WEEK · {p.week}</div>
      <h1 className="h1">{p.plan.title}</h1>
      <p className="muted">{p.plan.why}</p>
      <div className="small"><strong>Tools:</strong> {p.plan.tools.join(', ')}</div>
      <ol className="checklist">
        {p.plan.steps.map((s, i) => (
          <li key={i}>
            <label>
              <input type="checkbox" checked={p.done[i]} onChange={() => run(() => api.toggleStep(i))} />
              <span className={p.done[i] ? 'step-done' : ''}>{s}</span>
            </label>
          </li>
        ))}
      </ol>
      <div className="why"><strong>Done when: </strong><span className="muted">{p.plan.done_when}</span></div>
      <div className="actions">
        {p.completed ? (
          <button type="button" className="btn" onClick={() => run(() => api.completeProject(false))}>Mark as not built</button>
        ) : (
          <button type="button" className="btn btn-primary" disabled={!allDone} onClick={() => run(() => api.completeProject(true))}>
            {allDone ? 'Mark as built' : 'Tick every step to finish'}
          </button>
        )}
      </div>
      {p.completed && <div className="accent small">Built. It's on your Built list and counts toward your skills radar.</div>}
      {e2 && <div className="error">{e2}</div>}
      <p className="muted tiny">A new project is compiled from each week's news every Monday. Unfinished ones simply stay in the past: no guilt pile.</p>
    </section>
  )
}

export function BacklogPage() {
  const [tab, setTab] = useState<'active' | 'archived'>('active')
  const [items, setItems] = useState<Idea[]>([])
  const [err, setErr] = useState<string | null>(null)
  const load = (t = tab) => api.ideas(t).then(setItems).catch((e) => setErr(errText(e)))
  useEffect(() => { void load(tab) }, [tab]) // eslint-disable-line react-hooks/exhaustive-deps
  const act = (fn: () => Promise<unknown>) => fn().then(() => load()).catch((e) => setErr(errText(e)))
  return (
    <section className="panel page">
      <div className="panel-head">
        <h1 className="h1">Idea backlog</h1>
        <div className="seg" role="group" aria-label="Backlog view">
          <button type="button" className={tab === 'active' ? 'seg-on' : ''} aria-pressed={tab === 'active'} onClick={() => setTab('active')}>Active</button>
          <button type="button" className={tab === 'archived' ? 'seg-on' : ''} aria-pressed={tab === 'archived'} onClick={() => setTab('archived')}>Archive</button>
        </div>
      </div>
      <p className="muted small">
        {tab === 'active'
          ? 'Capped at 10. Untouched ideas expire after 21 days unless starred, so this never piles up.'
          : 'Dismissed and expired ideas. Restore one, or delete it for good.'}
      </p>
      {err && <div className="error">{err}</div>}
      {items.length === 0 && <div className="muted">Nothing here.</div>}
      {items.map((i) => (
        <div key={i.id} className="idea idea-big">
          <div className="idea-text">
            <div>{i.title}</div>
            <div className="small muted">{i.detail}</div>
            <div className="tiny muted">
              {tab === 'active'
                ? i.starred ? 'Starred · kept until you remove it' : `Expires in ${i.expires_in_days} days`
                : i.reason === 'expired' ? 'Expired' : 'Dismissed'}
            </div>
          </div>
          {tab === 'active' ? (
            <>
              <button type="button" className={`icon-btn ${i.starred ? 'on' : ''}`} aria-label={i.starred ? 'Unstar idea' : 'Keep idea'} aria-pressed={i.starred} onClick={() => act(() => api.starIdea(i.id, !i.starred))}>★</button>
              <button type="button" className="icon-btn" aria-label="Dismiss idea" onClick={() => act(() => api.dismissIdea(i.id))}>✕</button>
            </>
          ) : (
            <>
              <button type="button" className="btn" onClick={() => act(async () => { if (!(await api.restoreIdea(i.id))) setErr('Backlog is full (10). Dismiss one first.') })}>Restore</button>
              <button type="button" className="btn btn-danger" onClick={() => act(() => api.deleteIdea(i.id))}>Delete</button>
            </>
          )}
        </div>
      ))}
    </section>
  )
}

export function BuiltPage() {
  const [items, , err] = useLoad<BuiltItem[]>(api.built)
  return (
    <section className="panel page">
      <h1 className="h1">Built</h1>
      <p className="muted small">Finished weekly projects: your portfolio, ready to write up on GitHub.</p>
      {err && <div className="error">{err}</div>}
      {items?.length === 0 && <div className="muted">Nothing built yet. Finish a project of the week to see it here.</div>}
      {items?.map((b) => (
        <div key={b.week} className="row">
          <div>{b.title}</div>
          <div className="mono tiny muted">{b.week} · {fmtDate(b.completed_at)}</div>
        </div>
      ))}
    </section>
  )
}

export function RecapPage() {
  const [r, , err] = useLoad<Recap>(api.recap)
  const [picked, setPicked] = useState<Record<number, number>>({})
  if (err) return <div className="error">{err}</div>
  if (!r) return <div className="muted">Loading…</div>
  return (
    <section className="panel page">
      <h1 className="h1">Weekly recap</h1>
      <p className="muted small">{r.ready ? "It's Sunday: here's your week." : `Preview. The full recap lands in ${r.days_until} days.`} {r.story_count} stories in the last 7 days.</p>
      {r.themes.map((t) => (
        <div key={t.theme} className="row">
          <div><strong>{t.theme}</strong> <span className="muted small">· {t.count} stories</span></div>
          {t.examples.map((e) => <div key={e} className="small muted">• {e}</div>)}
        </div>
      ))}
      {r.questions.length > 0 && <h2 className="mono h2 spaced">3 QUESTIONS</h2>}
      {r.questions.map((q, qi) => (
        <div key={qi} className="row">
          <div className="small">{q.question}</div>
          <div className="quiz-opts">
            {q.options.map((o, i) => {
              const ans = picked[qi]
              const state = ans === undefined ? '' : i === q.answer ? 'opt-right' : i === ans ? 'opt-wrong' : ''
              return <button key={i} type="button" className={`opt ${state}`} disabled={ans !== undefined} onClick={() => setPicked({ ...picked, [qi]: i })}>{o}</button>
            })}
          </div>
          {picked[qi] !== undefined && <div className="small muted">{q.explanation}</div>}
        </div>
      ))}
    </section>
  )
}

export function RadarPage() {
  const [rows, , err] = useLoad<RadarRow[]>(api.radar)
  const max = Math.max(1, ...(rows ?? []).map((r) => r.mentions))
  const gaps = (rows ?? []).filter((r) => r.mentions > 0 && !r.built).slice(0, 3)
  return (
    <section className="panel page">
      <h1 className="h1">Skills radar</h1>
      <p className="muted small">What the news kept talking about in the last 30 days, against what you've built.</p>
      {err && <div className="error">{err}</div>}
      {gaps.length > 0 && <div className="why"><strong>Learn next: </strong><span className="muted">{gaps.map((g) => g.theme).join(', ')}</span></div>}
      {rows?.map((r) => (
        <div key={r.key} className="radar-row">
          <div className="radar-label small">{r.theme}</div>
          <div className="bar radar-bar"><div className={`bar-fill ${r.built ? '' : 'bar-dim'}`} style={{ width: `${(r.mentions / max) * 100}%` }} /></div>
          <div className="mono tiny radar-n">{r.mentions}{r.built ? ' ✓' : ''}</div>
        </div>
      ))}
      <p className="muted tiny">✓ = you've built a project on this theme.</p>
    </section>
  )
}

export function GlossaryPage() {
  const [terms, , err] = useLoad<Term[]>(api.glossary)
  const [q, setQ] = useState('')
  const shown = (terms ?? []).filter((t) => (t.term + t.plain).toLowerCase().includes(q.toLowerCase()))
  return (
    <section className="panel page">
      <h1 className="h1">Glossary</h1>
      <label className="ask-field">
        <span className="mono small muted">FIND</span>
        <input type="search" value={q} maxLength={60} onChange={(e) => setQ(e.target.value)} placeholder="e.g. lateral" />
      </label>
      {err && <div className="error">{err}</div>}
      {shown.map((t) => (
        <div key={t.term} className="row">
          <div><strong>{t.term}</strong></div>
          <div className="small">{t.plain}</div>
          {t.analogy && <div className="small muted">Think of it as: {t.analogy}</div>}
        </div>
      ))}
    </section>
  )
}

export function WatchlistPage({ onChange }: { onChange: () => void }) {
  const [list, setList, err] = useLoad<string[]>(api.watchlist)
  const [term, setTerm] = useState('')
  const [e2, setE2] = useState<string | null>(null)
  const add = () => api.addWatch(term).then((l) => { setList(l); setTerm(''); setE2(null); onChange() }).catch((e) => setE2(errText(e)))
  return (
    <section className="panel page">
      <h1 className="h1">Watchlist</h1>
      <p className="muted small">Vendors and tech you care about. Matching stories rank higher and get a watchlist tag. Stored only on this computer.</p>
      <form className="ask" onSubmit={(e) => { e.preventDefault(); void add() }}>
        <label className="ask-field">
          <span className="mono small muted">ADD</span>
          <input type="text" value={term} maxLength={40} onChange={(e) => setTerm(e.target.value)} placeholder="e.g. Fortinet, Wazuh, Azure" />
        </label>
        <button type="submit" className="btn btn-primary" disabled={!term.trim()}>Add</button>
      </form>
      {(err || e2) && <div className="error">{err || e2}</div>}
      <div className="chips">
        {list?.map((t) => (
          <span key={t} className="chip chip-static">
            {t}
            <button type="button" className="chip-x" aria-label={`Remove ${t}`} onClick={() => api.removeWatch(t).then((l) => { setList(l); onChange() })}>✕</button>
          </span>
        ))}
        {list?.length === 0 && <span className="muted small">Empty. Try: microsoft, fortinet, wazuh, cloud.</span>}
      </div>
    </section>
  )
}

function UpdatesSection() {
  const [version, setVersion] = useState('')
  const [info, setInfo] = useState<UpdateInfo | null>(null)
  const [busy, setBusy] = useState<'checking' | 'installing' | null>(null)
  const [err, setErr] = useState<string | null>(null)
  useEffect(() => { api.appVersion().then(setVersion).catch(() => {}) }, [])
  const check = () => {
    setBusy('checking'); setErr(null)
    api.checkUpdate().then(setInfo).catch((e) => setErr(errText(e))).finally(() => setBusy(null))
  }
  const install = () => {
    setBusy('installing'); setErr(null)
    api.installUpdate().catch((e) => { setErr(errText(e)); setBusy(null) })
  }
  return (
    <>
      <h2 className="mono h2 spaced">UPDATES</h2>
      <p className="small">Installed version: <span className="mono">{version || '…'}</span></p>
      <p className="tiny muted">
        Sitrep never checks by itself. Updates come only from this project's GitHub Releases, and each one must carry a valid signature or it is refused.
      </p>
      {info && !info.available && <p className="small accent">You're on the latest version.</p>}
      {info?.available && (
        <div className="why">
          <strong>Version {info.available} is available.</strong>
          {info.notes && <div className="small muted" style={{ whiteSpace: 'pre-line', marginTop: 6 }}>{info.notes}</div>}
        </div>
      )}
      <div className="actions" style={{ justifyContent: 'flex-start' }}>
        <button type="button" className="btn" disabled={busy !== null} onClick={check}>
          {busy === 'checking' ? 'Checking…' : 'Check for updates'}
        </button>
        {info?.available && (
          <button type="button" className="btn btn-primary" disabled={busy !== null} onClick={install}>
            {busy === 'installing' ? 'Installing… Sitrep will restart' : `Install ${info.available}`}
          </button>
        )}
      </div>
      {err && <div className="error">{err}</div>}
    </>
  )
}

export function SettingsPage({ onAiChange }: { onAiChange: () => void }) {
  const [ai, setAi, err, reloadAi] = useLoad<AiStatus>(api.aiStatus)
  const [sources] = useLoad(api.sources)
  const [e2, setE2] = useState<string | null>(null)
  const save = (enabled: boolean, model: string) =>
    api.setAi(enabled, model).then(() => { if (ai) setAi({ ...ai, enabled, model }); onAiChange() }).catch((e) => setE2(errText(e)))
  return (
    <section className="panel page">
      <h1 className="h1">Settings</h1>

      <h2 className="mono h2 spaced">LOCAL AI</h2>
      {err && <div className="error">{err}</div>}
      {ai && (
        <>
          <p className="small">
            Status: {ai.running ? <span className="accent">Ollama running · {ai.models.length} model(s)</span> : <span className="amber">Ollama not found</span>}
          </p>
          {!ai.running && (
            <p className="small muted">
              Sitrep works without AI (it uses the source's own summary). For plain-English rewrites, Simple/Deeper versions and Ask, install the free
              Ollama app from ollama.com, then run <code>ollama pull llama3.2:3b</code>. Everything stays on your computer.
            </p>
          )}
          <label className="check">
            <input type="checkbox" checked={ai.enabled} onChange={(e) => void save(e.target.checked, ai.model)} />
            Use local AI when available
          </label>
          {ai.models.length > 0 && (
            <label className="field">
              <span className="small muted">Model</span>
              <select value={ai.models.includes(ai.model) ? ai.model : ai.models[0]} onChange={(e) => void save(ai.enabled, e.target.value)}>
                {ai.models.map((m) => <option key={m} value={m}>{m}</option>)}
              </select>
            </label>
          )}
          <label className="check">
            <input
              type="checkbox"
              checked={ai.full_articles}
              onChange={(e) => {
                const on = e.target.checked
                api.setFullArticles(on).then(() => setAi({ ...ai, full_articles: on })).catch((er) => setE2(errText(er)))
              }}
            />
            Read the full article for today's 3 stories (better summaries)
          </label>
          <p className="tiny muted">
            Only fetched from the same five news sites as the feeds, never from other links. Cloud models are always blocked.
          </p>
          <button type="button" className="btn" onClick={() => { reloadAi(); onAiChange() }}>Check again</button>
        </>
      )}
      {e2 && <div className="error">{e2}</div>}

      <UpdatesSection />

      <h2 className="mono h2 spaced">PRIVACY</h2>
      <ul className="small muted plain-list">
        <li>No account, no analytics, no tracking. Your reading history, backlog and watchlist stay in a local database on this computer.</li>
        <li>The only internet traffic is downloading the public feeds below and, if enabled, the full text of today's 3 stories from those same news sites.</li>
        <li>The AI runs only on this computer (127.0.0.1). Ollama "cloud" models are blocked so article text never leaves your PC.</li>
        <li>Article links open in your normal browser only when you click "Read source".</li>
      </ul>

      <h2 className="mono h2 spaced">SOURCES</h2>
      <ul className="small plain-list">
        {sources?.map((s) => <li key={s.url}>{s.name} <span className="muted tiny mono">{s.url}</span></li>)}
      </ul>
    </section>
  )
}
