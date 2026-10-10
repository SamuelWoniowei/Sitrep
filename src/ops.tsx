import { useEffect, useState } from 'react'
import { STAGES } from './StoryCard'
import { FunFact } from './fx'
import { api, errText, type ActorSeen, type AiStatus, type Cluster, type HuntResult, type WatchRow, type LabPackResult, type Project, type Systems, type VoiceStatus, type WeekStory } from './api'

function useLoad<T>(fn: () => Promise<T>): [T | null, string | null] {
  const [data, setData] = useState<T | null>(null)
  const [err, setErr] = useState<string | null>(null)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { fn().then(setData).catch((e) => setErr(errText(e))) }, [])
  return [data, err]
}

export function IntelWall({ go }: { go: (p: 'developing' | 'actors' | 'affected' | 'watchlist') => void }) {
  const [dev] = useLoad<Cluster[]>(api.developing)
  const [actors] = useLoad<ActorSeen[]>(api.actors)
  const [watch] = useLoad<WatchRow[]>(api.watchBoard)
  return (
    <>
      <section className="panel">
        <div className="panel-row mono small"><span className="muted">DEVELOPING</span><button type="button" className="linkish" onClick={() => go('developing')}>all →</button></div>
        {dev?.length === 0 && <div className="muted small">Nothing is developing right now.</div>}
        {dev?.slice(0, 3).map((c) => (
          <div key={c.first + c.title} className="wall-row">
            <div className="small">{c.title}</div>
            <div className="mono tiny muted">DAY {c.days} · {c.items.length} REPORTS{c.new_count ? <span className="accent"> · {c.new_count} NEW</span> : ''}</div>
          </div>
        ))}
      </section>
      <section className="panel">
        <div className="panel-row mono small"><span className="muted">THREAT ACTORS · 14 DAYS</span><button type="button" className="linkish" onClick={() => go('actors')}>all →</button></div>
        {actors?.length === 0 && <div className="muted small">No known groups named lately.</div>}
        {actors?.slice(0, 4).map((a) => (
          <div key={a.name} className="wall-row wall-flex">
            <span className="small"><strong>{a.name}</strong> <span className="muted">· {a.origin.split(',')[0]}</span></span>
            <span className={`tag ${a.kind === 'Criminal' ? 'tag-amber' : 'tag-blue'}`}>{a.stories.length}</span>
          </div>
        ))}
      </section>
      <section className="panel">
        <div className="panel-row mono small"><span className="muted">WATCHLIST PULSE</span><button type="button" className="linkish" onClick={() => go('watchlist')}>board →</button></div>
        {watch?.length === 0 && <div className="muted small">Add vendors you care about on the Watchlist.</div>}
        {watch?.slice(0, 4).map((w) => (
          <div key={w.term} className="wall-row wall-flex">
            <span className="small">{w.term}</span>
            <span className="wall-spark">{w.per_day.map((n, i) => <span key={i} className="spark-bar" style={{ height: `${Math.max(10, n * 40)}%`, opacity: n ? 1 : 0.25 }} />)}</span>
            <span className="mono small">{w.total}</span>
          </div>
        ))}
      </section>
      <section className="panel panel-accent">
        <div className="mono small muted">AM I AFFECTED?</div>
        <div className="small">Check this PC against flaws attackers are using right now.</div>
        <button type="button" className="btn btn-primary" onClick={() => go('affected')}>Check this PC →</button>
      </section>
    </>
  )
}

const fmt = (ts: number) => new Date(ts * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })

/** Plays a developing story back day by day: reports appear, attack stages light up. */
function Replay({ c }: { c: Cluster }) {
  const [day, setDay] = useState(1)
  const [playing, setPlaying] = useState(false)
  useEffect(() => {
    if (!playing) return
    const t = window.setInterval(() => {
      setDay((d) => {
        if (d >= c.days) { setPlaying(false); return d }
        return d + 1
      })
    }, 1100)
    return () => window.clearInterval(t)
  }, [playing, c.days])
  const shown = c.items.filter((i) => i.day <= day)
  const text = shown.map((i) => i.title).join(' ')
  const lit = STAGES.map((s) => s.words.test(text))
  const pct = (d: number) => (c.days <= 1 ? 50 : ((d - 1) / (c.days - 1)) * 100)
  return (
    <div className="replay">
      <div className="replay-bar">
        <button type="button" className="btn btn-primary" onClick={() => { if (day >= c.days) setDay(1); setPlaying(!playing) }}>
          {playing ? '❚❚ Pause' : day >= c.days ? '↺ Replay' : '▶ Play'}
        </button>
        <span className="mono small">DAY {day} / {c.days}</span>
        <input type="range" min={1} max={Math.max(1, c.days)} value={day} aria-label="Day" onChange={(e) => { setPlaying(false); setDay(Number(e.target.value)) }} />
      </div>
      <div className="replay-track" aria-hidden="true">
        <span className="replay-line" />
        {c.items.map((i) => <span key={i.id} className={`replay-dot ${i.day <= day ? 'on' : ''}`} style={{ left: `${pct(i.day)}%` }} />)}
        <span className="replay-head" style={{ left: `${pct(day)}%` }} />
      </div>
      <ol className="flow">
        {STAGES.map((s, i) => (
          <li key={s.label} className={`flow-step ${lit[i] ? 'flow-on' : ''}`}>
            <span className="flow-dot" /><span className="small">{s.label}</span>
            <span className="tiny muted">{lit[i] ? 'seen so far' : 'not yet'}</span>
          </li>
        ))}
      </ol>
      <ul className="replay-list">
        {shown.map((i) => (
          <li key={i.id} className={i.day === day ? 'replay-now' : ''}>
            <span className="mono tiny muted">DAY {i.day} · {i.source}</span>
            <div className="small">{i.title}</div>
          </li>
        ))}
      </ul>
      <p className="tiny muted">A replay of how the news unfolded. Stages are estimated from the report titles, so treat it as a guide.</p>
    </div>
  )
}

export function DevelopingPage() {
  const [clusters, err] = useLoad<Cluster[]>(api.developing)
  const [open, setOpen] = useState<string | null>(null)
  return (
    <section className="panel page">
      <h1 className="h1">Developing stories</h1>
      <p className="muted small">Stories that keep moving: several reports about the same flaw or incident, laid out by day. "New" means you have already read an earlier report and this one came after it.</p>
      {err && <div className="error">{err}</div>}
      {clusters?.length === 0 && <p className="muted">Nothing is developing right now. Stories appear here once two or more reports cover the same thing.</p>}
      {clusters?.map((c) => (
        <div key={c.first + c.title} className={`card ${open === c.first + c.title ? 'card-open' : ''}`}>
          <div className="panel-head">
            <strong className="actor-name">{c.title}</strong>
            {c.new_count > 0 && <span className="tag tag-green">{c.new_count} NEW SINCE YOU READ</span>}
          </div>
          <div className="mono tiny muted">DAY 1 → DAY {c.days} · {c.items.length} REPORTS{c.cves.length ? ` · ${c.cves.join(' · ')}` : ''}</div>
          <div className={open === c.first + c.title ? 'dev-split' : ''}>
          <div>
          <ol className="timeline">
            {c.items.map((i) => (
              <li key={i.id} className={`tl-item ${i.new ? 'tl-new' : ''}`}>
                <span className="tl-dot" aria-hidden="true" />
                <div className="mono tiny muted">DAY {i.day} · {fmt(i.published)} · {i.source}{i.read ? ' · READ' : ''}{i.new ? ' · NEW' : ''}</div>
                <button type="button" className="linkish small" onClick={() => void api.openStory(i.id)}>{i.title}</button>
              </li>
            ))}
          </ol>
          <div className="actions">
            <button type="button" className="btn" onClick={() => setOpen(open === c.first + c.title ? null : c.first + c.title)}>
              {open === c.first + c.title ? 'Close replay' : '▶ Attack replay'}
            </button>
          </div>
          </div>
          {open === c.first + c.title && <Replay c={c} />}
          </div>
        </div>
      ))}
    </section>
  )
}

export function HuntPage() {
  const [res, setRes] = useState<HuntResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const run = () => {
    setBusy(true)
    setMsg('')
    api.huntLogs()
      .then((r) => { if (r) setRes(r); else setMsg('No file chosen.') })
      .catch((e) => setMsg(errText(e)))
      .finally(() => setBusy(false))
  }
  const mb = (b: number) => (b / 1048576).toFixed(1)
  return (
    <section className="panel page">
      <h1 className="h1">Log hunt</h1>
      <div className="dash">
        <div className="card">
          <h2 className="mono h2 spaced">SCAN A LOG FILE</h2>
          <p className="small muted">Pick a log from your lab (Suricata <code>eve.json</code>, Wazuh <code>alerts.json</code>, a firewall or proxy log, a CSV). Sitrep looks for any IP, domain or file hash that was named in the last 30 days of security stories, and shows you where it appears.</p>
          <button type="button" className="btn btn-primary" disabled={busy} onClick={run}>{busy ? 'Scanning…' : 'Choose a log file…'}</button>
          {busy && <div className="scanbar" role="status" aria-label="Scanning the log"><span /></div>}
          {msg && <div className="error small">{msg}</div>}
        </div>
        <div className="dash-side">
          <div className="card">
            <h2 className="mono h2 spaced">PRIVATE BY DESIGN</h2>
            <ul className="small muted plain-list">
              <li>The file is read once on this computer and never copied or uploaded.</li>
              <li>Only short sample lines are shown here. Nothing is saved.</li>
              <li>Plain-text logs only (not Windows .evtx). Stops at 4 GB or 2 minutes.</li>
            </ul>
          </div>
          <div className="card">
            <h2 className="mono h2 spaced">WHERE TO FIND LOGS</h2>
            <ul className="small muted plain-list">
              <li>Suricata: <code>/var/log/suricata/eve.json</code></li>
              <li>Wazuh manager: <code>/var/ossec/logs/alerts/alerts.json</code></li>
              <li>Firewall or proxy: export a day as .log or .csv</li>
              <li>Windows events: export to CSV first (the app reads plain text only).</li>
            </ul>
          </div>
          <div className="card">
            <h2 className="mono h2 spaced">HOW TO READ A MATCH</h2>
            <p className="small muted">A match means "this indicator was named in the news and also appears in your log". It is a lead, not proof. Check the time, the host and the story before you act.</p>
          </div>
          <FunFact className="card" />
        </div>
      </div>
      {res && (
        <div className="card span-all">
          <div className="panel-head">
            <strong className="actor-name">{res.file}</strong>
            <span className={`tag ${res.hits.length ? 'tag-red' : 'tag-green'}`}>{res.hits.length ? `${res.hits.length} MATCHES` : 'NO MATCHES'}</span>
          </div>
          <div className="mono tiny muted">{res.lines.toLocaleString()} LINES · {mb(res.bytes)} MB · {res.checked.toLocaleString()} INDICATORS CHECKED{res.truncated ? ' · STOPPED EARLY' : ''}</div>
          {res.hits.length === 0 && <p className="small">Nothing in this file matches indicators from recent stories. That is good news, but it only covers what the news has named, so it is not proof of a clean system.</p>}
          <div className="cols-2">
            {res.hits.map((h) => (
              <div key={h.ioc} className="row hit">
                <div><span className="mono">{h.ioc}</span> <span className="tag tag-grey">{h.kind.toUpperCase()}</span></div>
                <div className="small">{h.count.toLocaleString()} {h.count === 1 ? 'time' : 'times'} · first at line {h.first_line.toLocaleString()}</div>
                <code className="hit-sample">{h.sample}</code>
                <div className="tiny muted">From story: {h.story_title}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  )
}

export function LabPackPage() {
  const [stories, err] = useLoad<WeekStory[]>(api.weekStories)
  const [project] = useLoad<Project | null>(api.project)
  const [done, setDone] = useState<Record<string, LabPackResult | string>>({})
  const [busy, setBusy] = useState('')
  const make = (id: string) => {
    setBusy(id)
    api.labPack(id)
      .then((r) => setDone((d) => ({ ...d, [id]: r })))
      .catch((e) => setDone((d) => ({ ...d, [id]: errText(e) })))
      .finally(() => setBusy(''))
  }
  return (
    <section className="panel page">
      <h1 className="h1">Weekly lab pack</h1>
      <p className="muted small">Turn this week's stories into things you can try in your own lab. A pack is saved in Documents/Sitrep and holds the indicators found in the story, draft Suricata rules, Wazuh lists and rules, a CSV and a README. Nothing is sent anywhere, and nothing is run for you.</p>
      {project && (
        <div className="card span-all">
          <div className="mono tiny accent">THIS WEEK'S PROJECT</div>
          <strong className="actor-name">{project.plan.title}</strong>
          <div className="small muted">{project.plan.why}</div>
          <div className="small"><strong>Tools:</strong> {project.plan.tools.join(', ')} · {project.done.filter(Boolean).length}/{project.done.length} steps done</div>
        </div>
      )}
      {err && <div className="error">{err}</div>}
      {stories?.length === 0 && <p className="muted">No stories this week carry a CVE or indicators yet.</p>}
      {stories?.map((s) => {
        const r = done[s.id]
        return (
          <div key={s.id} className="card">
            <div className="small"><strong>{s.headline}</strong></div>
            <div className="mono tiny muted">{fmt(s.published)} · {s.iocs} INDICATORS{s.cves.length ? ` · ${s.cves.join(' · ')}` : ''}</div>
            <div className="actions">
              <button type="button" className="btn" disabled={busy === s.id} onClick={() => make(s.id)}>{busy === s.id ? 'Building…' : 'Build lab pack'}</button>
            </div>
            {typeof r === 'string' && <div className="error small">{r}</div>}
            {r && typeof r !== 'string' && <div className="small accent">Saved: {r.ips} IPs, {r.domains} domains, {r.hashes} hashes. Folder: {r.folder}</div>}
          </div>
        )
      })}
    </section>
  )
}

function Row({ k, v, ok }: { k: string; v: string; ok?: boolean }) {
  return <div className="sys-row"><span className="small muted">{k}</span><span className={`small ${ok === undefined ? '' : ok ? 'accent' : 'amber'}`}>{v}</span></div>
}

export function SystemsPage() {
  const [ai] = useLoad<AiStatus>(api.aiStatus)
  const [voice] = useLoad<VoiceStatus>(api.voiceStatus)
  const [sys, err] = useLoad<Systems>(api.systems)
  const [ver] = useLoad<string>(api.appVersion)
  const ago = (ts: number) => {
    if (!ts) return 'never'
    const m = Math.round((Date.now() / 1000 - ts) / 60)
    return m < 1 ? 'just now' : m < 120 ? `${m} min ago` : `${Math.round(m / 60)} h ago`
  }
  return (
    <section className="panel page">
      <h1 className="h1">Systems</h1>
      <p className="muted small">Everything Sitrep depends on, and whether it is working.</p>
      {err && <div className="error">{err}</div>}
      <div className="card">
        <h2 className="mono h2 spaced">LOCAL AI</h2>
        <Row k="Ollama" v={ai ? (ai.running ? 'running' : 'not found') : '…'} ok={ai?.running} />
        <Row k="Model" v={ai?.model || 'none'} />
        <Row k="Use AI" v={ai ? (ai.enabled ? 'on' : 'off') : '…'} />
        <Row k="Full articles" v={ai ? (ai.full_articles ? 'on' : 'off') : '…'} />
      </div>
      <div className="card">
        <h2 className="mono h2 spaced">VOICE</h2>
        <Row k="Natural voice" v={voice ? (voice.installed ? voice.voice : 'not installed') : '…'} ok={voice?.installed} />
        <Row k="Fallback" v="on-device system voice only" />
      </div>
      <div className="card">
        <h2 className="mono h2 spaced">NEWS FEEDS</h2>
        <Row k="Sources" v={sys ? String(sys.sources) : '…'} />
        <Row k="Last sync" v={sys ? ago(sys.last_sync) : '…'} ok={sys ? sys.last_sync > 0 && Date.now() / 1000 - sys.last_sync < 7200 : undefined} />
        <Row k="Auto-sync" v="every 30 min while open" />
      </div>
      <div className="card">
        <h2 className="mono h2 spaced">LOCAL DATABASE</h2>
        <Row k="Stories kept" v={sys ? String(sys.stories) : '…'} />
        <Row k="Exploited-flaw list" v={sys ? `${sys.kev} entries` : '…'} />
        <Row k="Stories you've read" v={sys ? String(sys.reads) : '…'} />
        <Row k="Oldest story" v={sys && sys.oldest ? fmt(sys.oldest) : 'none'} />
      </div>
      <div className="card">
        <h2 className="mono h2 spaced">APP</h2>
        <Row k="Version" v={ver ?? '…'} />
        <Row k="Updates" v="manual, signed only" ok />
        <Row k="Account / tracking" v="none" ok />
      </div>
      <div className="card">
        <h2 className="mono h2 spaced">SECURITY POSTURE</h2>
        <Row k="Network" v="fixed list of hosts only" ok />
        <Row k="Page rules (CSP)" v="strict, no inline scripts" ok />
        <Row k="AI" v="127.0.0.1 only, cloud blocked" ok />
        <Row k="Browser storage" v="not used" ok />
      </div>
    </section>
  )
}
