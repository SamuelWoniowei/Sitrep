import { useEffect, useState } from 'react'
import { api, errText, type AiStatus, type Cluster, type LabPackResult, type Project, type Systems, type VoiceStatus, type WeekStory } from './api'

function useLoad<T>(fn: () => Promise<T>): [T | null, string | null] {
  const [data, setData] = useState<T | null>(null)
  const [err, setErr] = useState<string | null>(null)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { fn().then(setData).catch((e) => setErr(errText(e))) }, [])
  return [data, err]
}

const fmt = (ts: number) => new Date(ts * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })

export function DevelopingPage() {
  const [clusters, err] = useLoad<Cluster[]>(api.developing)
  return (
    <section className="panel page">
      <h1 className="h1">Developing stories</h1>
      <p className="muted small">Stories that keep moving: several reports about the same flaw or incident, laid out by day. "New" means you have already read an earlier report and this one came after it.</p>
      {err && <div className="error">{err}</div>}
      {clusters?.length === 0 && <p className="muted">Nothing is developing right now. Stories appear here once two or more reports cover the same thing.</p>}
      {clusters?.map((c) => (
        <div key={c.first + c.title} className="card">
          <div className="panel-head">
            <strong className="actor-name">{c.title}</strong>
            {c.new_count > 0 && <span className="tag tag-green">{c.new_count} NEW SINCE YOU READ</span>}
          </div>
          <div className="mono tiny muted">DAY 1 → DAY {c.days} · {c.items.length} REPORTS{c.cves.length ? ` · ${c.cves.join(' · ')}` : ''}</div>
          <ol className="timeline">
            {c.items.map((i) => (
              <li key={i.id} className={`tl-item ${i.new ? 'tl-new' : ''}`}>
                <span className="tl-dot" aria-hidden="true" />
                <div className="mono tiny muted">DAY {i.day} · {fmt(i.published)} · {i.source}{i.read ? ' · READ' : ''}{i.new ? ' · NEW' : ''}</div>
                <button type="button" className="linkish small" onClick={() => void api.openStory(i.id)}>{i.title}</button>
              </li>
            ))}
          </ol>
        </div>
      ))}
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
