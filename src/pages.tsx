import { useEffect, useState } from 'react'
import { playParts, unlockAudio } from './listen'
import { CountUp, FunFact } from './fx'
import { animationsOn, setAnimations } from './prefs'
import { api, errText, type AiStatus, type UpdateInfo, type BuiltItem, type Idea, type Project, type RadarRow, type Recap, type GlossEntry, type ActorSeen, type ExposureResult, type VoiceStatus, type WatchRow, type DigestResult } from './api'

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
      <div className="dash">
      <div className="dash-main">
      <div className="card"><div className="mono small muted">STEPS · {p.done.filter(Boolean).length} OF {p.done.length}</div>
      <ol className="checklist">
        {p.plan.steps.map((s, i) => (
          <li key={i}>
            <label>
              <input type="checkbox" checked={p.done[i]} onChange={() => run(() => api.toggleStep(i))} />
              <span className={p.done[i] ? 'step-done' : ''}>{s}</span>
            </label>
            {p.resources?.[i]?.length > 0 && (
              <ul className="where">
                {p.resources[i].map((r) => (
                  <li key={r.name + r.at}><span className="mono tiny accent">WHERE TO LOOK</span> <strong className="small">{r.name}</strong> <span className="mono tiny muted">{r.at}</span><span className="tiny muted"> · {r.note}</span></li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ol></div>
        <div className="card"><div className="mono small muted">HOW TO TACKLE IT</div>
          <ul className="small muted plain-list">
            <li>Do the steps in order and stop after each one to write a line about what you saw.</li>
            <li>Keep it small. A rough version that works beats a perfect one that never ships.</li>
            <li>Put the result on GitHub with a short README. It is your portfolio.</li>
          </ul></div>
      </div>
      <div className="dash-side">
        <div className="card"><div className="mono small muted">PROGRESS</div>
          <div className="bar"><div className="bar-fill" style={{ width: `${(p.done.filter(Boolean).length / p.done.length) * 100}%` }} /></div>
          <div className="small muted">{p.completed ? 'Built.' : `${p.done.length - p.done.filter(Boolean).length} steps left`}</div></div>
        <div className="card"><div className="mono small muted">TOOLS</div><div className="chips">{p.plan.tools.map((t) => <span key={t} className="tag tag-grey">{t}</span>)}</div></div>
        <div className="card"><div className="mono small muted">DONE WHEN</div><div className="small">{p.plan.done_when}</div></div>
        <FunFact className="card" />
      </div>
      </div>
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

function DigestCard() {
  const [d, setD] = useState<DigestResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const make = () => {
    setBusy(true)
    setMsg('')
    api.exportDigest().then(setD).catch((e) => setMsg(errText(e))).finally(() => setBusy(false))
  }
  const copy = () => {
    if (!d) return
    navigator.clipboard.writeText(d.text).then(() => setMsg('Copied.')).catch(() => setMsg('Select the text and press Ctrl+C.'))
  }
  return (
    <div className="card span-all">
      <h2 className="mono h2 spaced">SHARE YOUR WEEK</h2>
      <p className="small muted">Builds a clean one-page digest of this week's top stories, themes and threat actors. You get a web page file (open it, print it to PDF, or host it anywhere) and plain text ready to paste into LinkedIn. It is made on this computer; nothing is uploaded. Add your name in Settings → You to put it on the page.</p>
      <div className="actions">
        <button type="button" className="btn btn-primary" disabled={busy} onClick={make}>{busy ? 'Building…' : 'Build this week\'s digest'}</button>
      </div>
      {msg && <p className="small muted">{msg}</p>}
      {d && (
        <>
          <p className="small accent">Saved {d.stories} stories for {d.week}. Folder: {d.folder}</p>
          <textarea className="digest-text" readOnly value={d.text} aria-label="Digest text" />
          <div className="actions"><button type="button" className="btn" onClick={copy}>Copy text</button></div>
        </>
      )}
    </div>
  )
}

export function RecapPage() {
  const [r, , err] = useLoad<Recap>(api.recap)
  const [picked, setPicked] = useState<Record<number, number>>({})
  if (err) return <div className="error">{err}</div>
  if (!r) return <div className="muted">Loading…</div>
  return (
    <section className="panel page">
      <h1 className="h1">Sunday Sitrep</h1>
      <button
        type="button"
        className="btn"
        onClick={() => { unlockAudio(); void playParts([`Your week in security. ${r.story_count} stories.`, ...r.themes.map((t) => `${t.theme}: ${t.count} stories. ${t.examples.slice(0, 2).join('. ')}`)], () => {}) }}
      >
        ▶ Listen to the recap
      </button>
      <p className="muted small">{r.ready ? "It's Sunday: here's your week." : `Preview. The full recap lands in ${r.days_until} days.`} {r.story_count} stories in the last 7 days.</p>
      <DigestCard />
      <div className="dash">
      <div className="card">
        <h2 className="mono h2 spaced">THEMES OF THE WEEK</h2>
        {r.themes.map((t) => (
          <div key={t.theme} className="theme">
            <div className="panel-row"><strong>{t.theme}</strong><span className="mono small muted">{t.count} stories</span></div>
            <div className="bar"><div className="bar-fill" style={{ width: `${(t.count / Math.max(1, ...r.themes.map((x) => x.count))) * 100}%` }} /></div>
            {t.examples.map((e) => <div key={e} className="small muted">• {e}</div>)}
          </div>
        ))}
      </div>
      <div className="dash-side">
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
      </div>
      </div>
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
      <div className="dash">
      <div className="card">
      <h2 className="mono h2 spaced">LAST 30 DAYS</h2>
      {rows?.map((r) => (
        <div key={r.key} className="radar-row">
          <div className="radar-label small">{r.theme}</div>
          <div className="bar radar-bar"><div className={`bar-fill ${r.built ? '' : 'bar-dim'}`} style={{ width: `${(r.mentions / max) * 100}%` }} /></div>
          <div className="mono tiny radar-n">{r.mentions}{r.built ? ' ✓' : ''}</div>
        </div>
      ))}
      <p className="muted tiny">✓ = you've built a project on this theme.</p>
      </div>
      <div className="dash-side">
        <div className="card panel-accent"><div className="mono small muted">LEARN NEXT</div>
          {gaps.length === 0 && <div className="small muted">Nothing standing out yet.</div>}
          {gaps.map((g) => <div key={g.key} className="small"><strong>{g.theme}</strong> <span className="muted">· {g.mentions} mentions, nothing built</span></div>)}
        </div>
        <div className="card"><div className="mono small muted">COVERAGE</div>
          <div className="watch-n"><span className="accent"><CountUp to={(rows ?? []).filter((r) => r.built).length} /></span><span className="small muted"> of {(rows ?? []).length} themes built</span></div>
        </div>
      </div>
      </div>
    </section>
  )
}

export function GlossaryPage() {
  const [terms, setTerms, err] = useLoad<GlossEntry[]>(api.glossary)
  const [q, setQ] = useState('')
  const [tab, setTab] = useState<'new' | 'learning' | 'known' | 'all'>('new')
  const [e2, setE2] = useState<string | null>(null)
  const set = (key: string, status: string) => api.setTermStatus(key, status).then(setTerms).catch((e) => setE2(errText(e)))
  const all = terms ?? []
  const count = (s: string) => all.filter((t) => t.status === s).length
  const shown = all
    .filter((t) => tab === 'all' || t.status === tab)
    .filter((t) => (t.term + t.plain).toLowerCase().includes(q.toLowerCase()))
  return (
    <section className="panel page">
      <h1 className="h1">Glossary</h1>
      <p className="small muted">Mark terms as you learn them. Known terms move out of your way. New terms the AI explains in stories are added here (up to 15 at a time) and tidy themselves away after 30 days if untouched.</p>
      <div className="chips">
        {(['new', 'learning', 'known', 'all'] as const).map((t) => (
          <button key={t} type="button" className={`chip ${tab === t ? 'chip-on' : ''}`} aria-pressed={tab === t} onClick={() => setTab(t)}>
            {t === 'all' ? `All ${all.length}` : `${t[0].toUpperCase()}${t.slice(1)} ${count(t)}`}
          </button>
        ))}
      </div>
      <label className="ask-field">
        <span className="mono small muted">FIND</span>
        <input type="search" value={q} maxLength={60} onChange={(e) => setQ(e.target.value)} placeholder="e.g. lateral" />
      </label>
      {(err || e2) && <div className="error">{err ?? e2}</div>}
      {shown.map((t) => (
        <div key={t.key} className="row">
          <div><strong>{t.term}</strong> {t.origin === 'ai' && <span className="tag tag-ai" title="Explained by your local AI">AI</span>}</div>
          <div className="small">{t.plain}</div>
          {t.analogy && <div className="small muted">Think of it as: {t.analogy}</div>}
          <div className="actions">
            {t.status !== 'learning' && <button type="button" className="btn" onClick={() => void set(t.key, 'learning')}>Learning</button>}
            {t.status !== 'known' && <button type="button" className="btn" onClick={() => void set(t.key, 'known')}>I know this</button>}
            {t.status !== 'new' && <button type="button" className="btn" onClick={() => void set(t.key, 'new')}>Reset</button>}
          </div>
        </div>
      ))}
      {terms && shown.length === 0 && <p className="muted small">Nothing here.</p>}
    </section>
  )
}

export function AffectedPage() {
  const [exp, setExp] = useState<ExposureResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [e2, setE2] = useState<string | null>(null)
  const check = () => {
    setBusy(true)
    setE2(null)
    api.exposure().then(setExp).catch((e) => setE2(errText(e))).finally(() => setBusy(false))
  }
  return (
    <section className="panel page">
      <h1 className="h1">Am I affected?</h1>
      <div className="dash">
      <div className="card">
      <h2 className="mono h2 spaced">SCAN</h2>
      <p className="small muted">Looks at the list of programs installed on this PC and compares their names with flaws attackers have recently started exploiting (CISA's list, last 90 days). It only reads names, keeps nothing, and sends nothing anywhere. It cannot check version numbers, so a match means "worth checking you are fully updated".</p>
      <button type="button" className="btn btn-primary" disabled={busy} onClick={check}>{busy ? 'Checking…' : 'Check this PC'}</button>
      {busy && <div className="scanbar" role="status" aria-label="Scanning installed programs"><span /></div>}
      {e2 && <div className="error small">{e2}</div>}
      {exp && !exp.supported && <p className="small muted">This check only works on Windows.</p>}
      {exp && exp.supported && (
        <>
          <p className="small">{exp.programs} programs checked. {exp.matches.length === 0 ? 'Nothing matched.' : `${exp.matches.length} worth a look:`}</p>
          {exp.matches.map((m) => (
            <div key={m.program} className="row">
              <div><strong>{m.program}</strong> {m.ransomware && <span className="tag tag-red">USED BY RANSOMWARE</span>}</div>
              <div className="small muted">Matches {m.vendor} {m.product} · latest flaw added {m.latest_added}</div>
              <div className="mono tiny">{m.cves.join(' · ')}</div>
              <div className="small">Update it to the newest version, then you're fine.</div>
            </div>
          ))}
        </>
      )}
      </div>

      <div className="dash-side">
        <div className="card">
          <h2 className="mono h2 spaced">HOW IT WORKS</h2>
          <ol className="small plain-list">
            <li>Reads the names of programs installed on this PC. Nothing else.</li>
            <li>Compares them with CISA's list of flaws attackers are exploiting (last 90 days).</li>
            <li>Shows matches. Nothing is saved or sent anywhere.</li>
          </ol>
        </div>
        <div className="card">
          <h2 className="mono h2 spaced">HOW TO READ IT</h2>
          <p className="small muted">A match means "this product has a flaw under attack". It cannot see your version number, so open the program, update it, and you are covered. No match is not a guarantee: it only knows about the exploited-flaw list.</p>
        </div>
        <div className="card">
          <h2 className="mono h2 spaced">GOOD HABITS</h2>
          <ul className="small muted plain-list">
            <li>Turn on automatic updates for browsers, Office and your PDF reader.</li>
            <li>Uninstall programs you no longer use. Fewer programs, fewer flaws.</li>
            <li>Routers and VPNs need updates too, and they get forgotten.</li>
          </ul>
        </div>
        <FunFact className="card" />
      </div>
      </div>
    </section>
  )
}

export function ActorsPage() {
  const [actors, , err] = useLoad<ActorSeen[]>(api.actors)
  return (
    <section className="panel page">
      <h1 className="h1">Threat actors</h1>
      <p className="muted small">Known groups named in stories over the last 14 days. These are public profiles, kept short; attribution is always the reporters' and vendors' judgement.</p>
      {err && <div className="error">{err}</div>}
      {actors && actors.length === 0 && <p className="small muted">No known groups named in recent stories.</p>}
      {actors?.map((a) => (
        <div key={a.name} className="card actor">
          <div><strong className="actor-name">{a.name}</strong> <span className={`tag ${a.kind === 'Criminal' ? 'tag-amber' : 'tag-blue'}`}>{a.kind.toUpperCase()}</span></div>
          <div className="small muted">{a.origin} · {a.stories.length} {a.stories.length === 1 ? 'story' : 'stories'} in 14 days</div>
          <div className="small">{a.blurb}</div>
          <div className="mono tiny accent">WHAT THEY WANT</div>
          <div className="small">{a.wants}</div>
          <div className="mono tiny accent">HOW THEY OPERATE</div>
          <div className="small">{a.how}</div>
          <div className="mono tiny muted">IN THE NEWS</div>
          <ul className="small muted plain-list">
            {a.stories.slice(0, 3).map(([id, t]) => <li key={id}>{t}</li>)}
          </ul>
        </div>
      ))}
    </section>
  )
}

function Spark({ v }: { v: number[] }) {
  const max = Math.max(1, ...v)
  return (
    <div className="spark" role="img" aria-label={`Mentions per day for the last 14 days: ${v.join(', ')}`}>
      {v.map((n, i) => <span key={i} className="spark-bar" style={{ height: `${Math.max(8, (n / max) * 100)}%`, opacity: n ? 1 : 0.25 }} />)}
    </div>
  )
}

export function WatchlistPage({ onChange }: { onChange: () => void }) {
  const [rows, setRows, err, reload] = useLoad<WatchRow[]>(api.watchBoard)
  const [term, setTerm] = useState('')
  const [e2, setE2] = useState<string | null>(null)
  const add = () => api.addWatch(term).then(() => { setTerm(''); setE2(null); reload(); onChange() }).catch((e) => setE2(errText(e)))
  return (
    <section className="panel page">
      <h1 className="h1">Watchlist board</h1>
      <p className="muted small">Vendors and tech you care about. Matching stories rank higher and get a watchlist tag. Each card shows the last 30 days. Stored only on this computer.</p>
      <form className="ask" onSubmit={(e) => { e.preventDefault(); void add() }}>
        <label className="ask-field">
          <span className="mono small muted">ADD</span>
          <input type="text" value={term} maxLength={40} onChange={(e) => setTerm(e.target.value)} placeholder="e.g. Fortinet, Wazuh, Azure" />
        </label>
        <button type="submit" className="btn btn-primary" disabled={!term.trim()}>Add</button>
      </form>
      {(err || e2) && <div className="error">{err || e2}</div>}
      {rows?.length === 0 && <span className="muted small">Empty. Try: microsoft, fortinet, wazuh, cloud.</span>}
      {rows?.map((r) => (
        <div key={r.term} className="card watch">
          <div className="panel-head">
            <strong className="actor-name">{r.term}</strong>
            <button type="button" className="chip-x" aria-label={`Remove ${r.term}`} onClick={() => api.removeWatch(r.term).then(() => { setRows(rows.filter((x) => x.term !== r.term)); onChange() })}>✕</button>
          </div>
          <div className="watch-n"><span className={r.total ? 'accent' : 'muted'}><CountUp to={r.total} /></span> <span className="small muted">{r.total === 1 ? 'story' : 'stories'} in 30 days</span></div>
          <Spark v={r.per_day} />
          <div className="mono tiny muted">LAST 14 DAYS</div>
          {r.latest.length === 0
            ? <div className="small muted">Quiet. Nothing recent.</div>
            : <ul className="small plain-list">{r.latest.map(([id, t]) => <li key={id}><button type="button" className="linkish" onClick={() => void api.openStory(id)}>{t}</button></li>)}</ul>}
        </div>
      ))}
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

function NameSection() {
  const [name, setName, err] = useLoad<string>(api.getName)
  const [msg, setMsg] = useState('')
  const save = () => api.setName(name ?? '').then((n) => { setName(n); setMsg('Saved.') }).catch((e) => setMsg(errText(e)))
  return (
    <>
      <h2 className="mono h2 spaced">YOU</h2>
      <p className="small muted">Your first name, for the greeting on Today. Stored only on this computer.</p>
      <form className="ask" onSubmit={(e) => { e.preventDefault(); void save() }}>
        <label className="ask-field">
          <span className="mono small muted">NAME</span>
          <input type="text" value={name ?? ''} maxLength={30} onChange={(e) => { setName(e.target.value); setMsg('') }} placeholder="e.g. Sam" />
        </label>
        <button type="submit" className="btn">Save</button>
      </form>
      {(err || msg) && <p className="small muted">{err ?? msg}</p>}
    </>
  )
}

function AnimationSection() {
  const [on, setOn] = useState(animationsOn())
  return (
    <>
      <h2 className="mono h2 spaced">MOTION</h2>
      <label className="check">
        <input type="checkbox" checked={on} onChange={(e) => { setOn(e.target.checked); void setAnimations(e.target.checked) }} />
        Animations (rotating globe, pulsing dots, ticker)
      </label>
      <p className="tiny muted">Also switched off automatically if your computer asks for reduced motion.</p>
    </>
  )
}

function FocusSection() {
  const [options] = useLoad(api.focusOptions)
  const [picked, setPicked, err] = useLoad(api.focus)
  const [e2, setE2] = useState<string | null>(null)
  const toggle = (r: string) => {
    if (!picked) return
    const next = picked.includes(r) ? picked.filter((x) => x !== r) : [...picked, r]
    api.setFocus(next).then(setPicked).catch((e) => setE2(errText(e)))
  }
  return (
    <>
      <h2 className="mono h2 spaced">CAREER FOCUS</h2>
      <p className="small muted">Pick the roles you care about. Summaries add a short "what this means for you" note for each. Applies to summaries written from now on.</p>
      <div className="chips">
        {options?.map((r) => (
          <button key={r} type="button" className={`chip ${picked?.includes(r) ? 'chip-on' : ''}`} aria-pressed={picked?.includes(r) ?? false} onClick={() => toggle(r)}>{r}</button>
        ))}
      </div>
      {(err || e2) && <div className="error small">{err ?? e2}</div>}
    </>
  )
}

function VoiceSection() {
  const [v, setV, err] = useLoad<VoiceStatus>(api.voiceStatus)
  const [busy, setBusy] = useState(false)
  const [e2, setE2] = useState<string | null>(null)
  const [testing, setTesting] = useState(false)
  const [testMsg, setTestMsg] = useState('')
  const test = () => {
    unlockAudio()
    setTesting(true)
    setTestMsg('')
    playParts(['This is Sitrep. If you can hear this, the voice is working.'], () => setTesting(false))
      .then((r) => { setTestMsg(r.message); if (!r.ok) setTesting(false) })
      .catch(() => { setTestMsg('Playback failed.'); setTesting(false) })
  }
  const run = (fn: () => Promise<VoiceStatus>) => {
    setBusy(true)
    setE2(null)
    fn().then(setV).catch((e) => setE2(errText(e))).finally(() => setBusy(false))
  }
  return (
    <>
      <h2 className="mono h2 spaced">VOICE</h2>
      {v && (
        <>
          <p className="small">
            {v.installed
              ? <>Natural voice: <span className="accent">{v.voice}</span>, running on this computer.</>
              : <>Natural voice not installed. Listen mode will use a built-in Windows voice that runs on this device (never an "Online" one).</>}
          </p>
          {!v.installed ? (
            <>
              <button type="button" className="btn btn-primary" disabled={busy} onClick={() => run(api.voiceInstall)}>
                {busy ? 'Downloading and checking…' : `Download natural voice (~${v.size_mb} MB, one time)`}
              </button>
              <p className="tiny muted">
                Downloads Piper from its official GitHub release and the Alan voice from its official Hugging Face page, then checks both against fixed checksums. Anything that does not match is deleted. After that it works offline.
              </p>
            </>
          ) : (
            <>
              <button type="button" className="btn btn-primary" disabled={busy || testing} onClick={test}>
                {testing ? 'Speaking…' : '▶ Test voice'}
              </button>
              <button type="button" className="btn" disabled={busy} onClick={() => run(api.voiceRemove)}>Remove voice</button>
            </>
          )}
          {testMsg && <p className="small muted">{testMsg}</p>}
        </>
      )}
      {(err || e2) && <div className="error small">{err ?? e2}</div>}
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

      <div className="card">
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
            Only fetched from the same news sites as the feeds, never from other links. Cloud models are always blocked.
          </p>
          <button type="button" className="btn" onClick={() => { reloadAi(); onAiChange() }}>Check again</button>
        </>
      )}
      {e2 && <div className="error">{e2}</div>}
      </div>

      <div className="card"><NameSection /></div>

      <div className="card"><FocusSection /></div>

      <div className="card"><VoiceSection /></div>

      <div className="card"><AnimationSection /></div>

      <div className="card"><UpdatesSection /></div>

      <div className="card">
      <h2 className="mono h2 spaced">PRIVACY</h2>
      <ul className="small muted plain-list">
        <li>No account, no analytics, no tracking. Your reading history, backlog and watchlist stay in a local database on this computer.</li>
        <li>The only internet traffic is downloading the public feeds below, CVE severity scores from NIST's NVD (only the CVE ID is sent) and, if enabled, the full text of today's 3 stories from those same news sites.</li>
        <li>The AI and the optional voice run only on this computer (the AI on 127.0.0.1). Ollama "cloud" models are blocked so article text never leaves your PC.</li>
        <li>Article links open in your normal browser only when you click "Read source".</li>
      </ul>
      </div>

      <div className="card">
      <h2 className="mono h2 spaced">SOURCES</h2>
      <ul className="small plain-list">
        {sources?.map((s) => <li key={s.url}>{s.name} <span className="muted tiny mono">{s.url}</span></li>)}
      </ul>
      </div>
    </section>
  )
}
