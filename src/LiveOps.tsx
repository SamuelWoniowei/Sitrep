import { CountUp, Gauge, Radar } from './fx'
import { useEffect, useState } from 'react'
import { api, errText, type ActorSeen, type LiveOps } from './api'
import { Globe } from './Globe'

function ago(ts: number): string {
  const d = Math.max(0, Math.round((Date.now() / 1000 - ts) / 86400))
  return d === 0 ? 'today' : `${d}d ago`
}

// Streak calendar: the last 16 weeks, one square per day, oldest on the left.
function Calendar({ days, today }: { days: string[]; today: string }) {
  const set = new Set(days)
  const end = new Date(today + 'T12:00:00')
  const cells: { key: string; on: boolean }[] = []
  for (let i = 111; i >= 0; i--) {
    const d = new Date(end)
    d.setDate(end.getDate() - i)
    const key = d.toISOString().slice(0, 10)
    cells.push({ key, on: set.has(key) })
  }
  return (
    <div className="cal" role="img" aria-label={`You read the brief on ${days.length} of the last 112 days`}>
      {cells.map((c) => <span key={c.key} className={`cal-cell ${c.on ? 'cal-on' : ''}`} title={c.key} />)}
    </div>
  )
}

// Actors on the left, CVEs on the right, a line when a story names both.
function Connections({ edges }: { edges: LiveOps['map']['edges'] }) {
  const actors = [...new Set(edges.map((e) => e.actor))].slice(0, 6)
  const cves = [...new Set(edges.filter((e) => actors.includes(e.actor)).map((e) => e.cve))].slice(0, 8)
  if (actors.length === 0) return <p className="small muted">No named group and CVE appeared together in recent stories.</p>
  const ay = (i: number) => 24 + i * 34
  const cy = (i: number) => 24 + i * (Math.max(actors.length * 34, 40) / Math.max(cves.length, 1)) * 0.95
  const h = Math.max(actors.length * 34, cves.length * 28) + 30
  return (
    <svg viewBox={`0 0 520 ${h}`} className="conn" role="img" aria-label="Which threat groups were named alongside which CVEs">
      {edges.filter((e) => actors.includes(e.actor) && cves.includes(e.cve)).map((e) => (
        <line key={e.actor + e.cve} x1={150} y1={ay(actors.indexOf(e.actor))} x2={370} y2={cy(cves.indexOf(e.cve))} className="conn-line" />
      ))}
      {actors.map((a, i) => <text key={a} x={140} y={ay(i) + 4} textAnchor="end" className="conn-text">{a}</text>)}
      {cves.map((c, i) => <text key={c} x={380} y={cy(i) + 4} className="conn-text conn-mono">{c}</text>)}
    </svg>
  )
}

function Stage({ on, label, sub }: { on: boolean; label: string; sub?: string }) {
  return (
    <div className={`stage ${on ? 'stage-on' : ''}`}>
      <span className="stage-dot" />
      <div className="small">{label}</div>
      {sub && <div className="tiny muted">{sub}</div>}
    </div>
  )
}

// Patch Tuesday is the second Tuesday of each month.
function nextPatchTuesday(from: Date): { date: Date; days: number } {
  for (let m = 0; m < 3; m++) {
    const first = new Date(from.getFullYear(), from.getMonth() + m, 1)
    const offset = (2 - first.getDay() + 7) % 7
    const d = new Date(first.getFullYear(), first.getMonth(), 1 + offset + 7)
    if (d.getTime() >= new Date(from.getFullYear(), from.getMonth(), from.getDate()).getTime()) {
      return { date: d, days: Math.round((d.getTime() - new Date(from.getFullYear(), from.getMonth(), from.getDate()).getTime()) / 86400000) }
    }
  }
  return { date: from, days: 0 }
}

// A simple, honest gauge: how many exploited flaws CISA added in the last 7 days.
function temperature(n: number): { label: string; cls: string } {
  if (n >= 12) return { label: 'HIGH', cls: 'red' }
  if (n >= 4) return { label: 'ELEVATED', cls: 'amber' }
  return { label: 'CALM', cls: 'accent' }
}

export function LiveOpsPage({ onOpenStory }: { onOpenStory: () => void }) {
  const [d, setD] = useState<LiveOps | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [sel, setSel] = useState<string | null>(null)
  const [actors, setActors] = useState<ActorSeen[]>([])
  useEffect(() => { api.actors().then(setActors).catch(() => setActors([])) }, [])
  useEffect(() => { api.liveops().then(setD).catch((e) => setErr(errText(e))) }, [])
  if (err) return <div className="error">{err}</div>
  if (!d) return <div className="muted">Loading…</div>
  const node = d.map.nodes.find((n) => n.id === sel) ?? null
  return (
    <section className="panel page page-wide">
      <h1 className="h1 h1-radar"><Radar /> Live ops</h1>
      <div className="tiles">
        <div className="tile" title="Based on how many exploited flaws CISA added in the last 7 days: under 4 calm, 4 to 11 elevated, 12 or more high.">
          <div className="mono tiny muted">THREAT TEMPERATURE</div>
          <Gauge value={d.exploited_14d} label={temperature(d.exploited_14d).label} />
          <div className={`tile-n ${temperature(d.exploited_14d).cls}`}>{temperature(d.exploited_14d).label}</div>
        </div>
        <div className="tile">
          <div className="mono tiny muted">NEXT PATCH TUESDAY</div>
          <div className="tile-n">{nextPatchTuesday(new Date()).days === 0 ? 'Today' : `${nextPatchTuesday(new Date()).days} days`}</div>
          <div className="tiny muted">{nextPatchTuesday(new Date()).date.toLocaleDateString('en-GB', { weekday: 'short', day: '2-digit', month: 'short' })}</div>
        </div>
        <div className="tile"><div className="mono tiny muted">SOURCES</div><div className="tile-n"><CountUp to={d.sources} /></div></div>
        <div className="tile"><div className="mono tiny muted">STREAK</div><div className="tile-n accent"><CountUp to={d.streak} /></div></div>
        <div className="tile"><div className="mono tiny muted">EXPLOITED FLAWS ADDED (7D)</div><div className="tile-n red"><CountUp to={d.exploited_14d} /></div></div>
        <div className="tile"><div className="mono tiny muted">NEW STORIES TODAY</div><div className="tile-n"><CountUp to={d.new_today} /></div></div>
        <div className="tile"><div className="mono tiny muted">COUNTRIES IN THE NEWS</div><div className="tile-n"><CountUp to={d.map.nodes.length} /></div></div>
      </div>

      <h2 className="mono h2 spaced">WHERE IN THE WORLD (14 DAYS)</h2>
      <p className="tiny muted">Dots are countries named in recent stories. Lines join a threat group's home country to other countries named in the same story. This shows what the news mentions together, not confirmed attack paths. Drag to turn, scroll to zoom.</p>
      <div className="globe-row">
        <Globe nodes={d.map.nodes} arcs={d.map.arcs} selected={sel} onSelect={setSel} />
        <div className="globe-side">
          {node ? (
            <>
              <h3 className="h3">{node.name}</h3>
              <p className="small muted">{node.count} {node.count === 1 ? 'story' : 'stories'} in 14 days</p>
              <ul className="small plain-list">{node.stories.map(([id, t]) => <li key={id}>{t}</li>)}</ul>
              <button type="button" className="btn" onClick={onOpenStory}>Back to today</button>
            </>
          ) : (
            <>
              <h3 className="h3">Most named</h3>
              <ul className="small plain-list">
                {d.map.nodes.slice(0, 12).map((n) => (
                  <li key={n.id}><button type="button" className="linkish" onClick={() => setSel(n.id)}>{n.name}</button> <span className="muted">· {n.count}</span></li>
                ))}
              </ul>
              {d.map.nodes.length === 0 && <p className="small muted">No countries named yet. Refresh to load stories.</p>}
            </>
          )}
        </div>
        <div className="globe-actors">
          <h3 className="h3">Threat actors in the news</h3>
          {actors.length === 0 && <p className="small muted">No known groups named in the last 14 days.</p>}
          {actors.slice(0, 6).map((a) => (
            <div key={a.name} className="actor-mini">
              <div className="actor-mini-top">
                <strong>{a.name}</strong>
                <span className={`tag ${a.kind === 'Criminal' ? 'tag-amber' : 'tag-blue'}`}>{a.kind.toUpperCase()}</span>
              </div>
              <div className="tiny muted">{a.origin} · {a.stories.length} {a.stories.length === 1 ? 'story' : 'stories'}</div>
              <div className="small">{a.blurb}</div>
            </div>
          ))}
        </div>
      </div>

      <h2 className="mono h2 spaced">FLAW LIFECYCLE</h2>
      {d.cves.length === 0 && <p className="small muted">No CVEs in recent stories.</p>}
      {d.cves.map((c) => (
        <div key={c.cve} className="row">
          <div><strong className="mono">{c.cve}</strong> <span className="muted small">{c.headline}</span></div>
          <div className="stages">
            <Stage on label="Reported" sub={ago(c.first_seen)} />
            <Stage on={c.score !== null} label={c.score !== null ? `${c.severity} ${c.score.toFixed(1)}` : 'Severity unknown'} />
            <Stage on={c.fix_mentioned} label="Fix mentioned" />
            <Stage on={c.exploited_on !== null} label={c.exploited_on ? `Exploited · listed ${c.exploited_on}` : 'Not known exploited'} />
            <Stage on={c.ransomware} label={c.ransomware ? 'Used by ransomware' : 'No ransomware link'} />
          </div>
        </div>
      ))}

      <h2 className="mono h2 spaced">GROUPS AND FLAWS NAMED TOGETHER</h2>
      <Connections edges={d.map.edges} />

      <h2 className="mono h2 spaced">YOUR LAST 16 WEEKS</h2>
      <Calendar days={d.calendar} today={d.today} />
      <p className="tiny muted">{d.calendar.length} of the last 112 days read.</p>
    </section>
  )
}
