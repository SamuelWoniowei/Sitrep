import { useCallback, useEffect, useRef, useState } from 'react'
import { api, errText, type NoteFeedback, type ShiftResult } from './api'
import type { Alert, Ev, ShiftDef, Verdict } from './shift/types'
import { LEVELS, SHIFTS } from './shift'
import {
  VERDICTS, VLABEL, alertById, exec, advance, endShift, evById, gradeAlert, gradeContain, isPinned, maxScore, newGame, noteFacts,
  openAlerts, reqMet, scn, submitVerdict, timeline, togglePin, total, visible, type Block, type Game, type Item, type Mode,
} from './shift/engine'

const hmShort = (ts: number): string => {
  const t = ((ts % 86400) + 86400) % 86400
  return `${String(Math.floor(t / 3600)).padStart(2, '0')}:${String(Math.floor((t % 3600) / 60)).padStart(2, '0')}`
}
const hmsOf = (dates: [string, string], ts: number): string => `${ts < 0 ? dates[0] : dates[1]} ${hmShort(ts)}:${String(((ts % 60) + 60) % 60).padStart(2, '0')}`
const rawTextOf = (dates: [string, string], e: Ev): string => `${hmsOf(dates, e.ts)}  ${e.src.padEnd(10)} ${Object.entries(e.f).map(([k, v]) => `${k}=${/[\s"]/.test(String(v)) ? `"${String(v).replace(/"/g, "'")}"` : v}`).join(' ')}`

function EvLine({ e, pinned, onPin, dates }: { e: Ev; pinned: boolean; onPin: (id: string) => void; dates: [string, string] }) {
  return (
    <button type="button" className={`sh-ln ${pinned ? 'sh-pin' : ''}`} onClick={() => onPin(e.id)} title="Click to pin as evidence" aria-pressed={pinned}>
      <span className="sh-tm">{hmsOf(dates, e.ts)}</span> <span className="sh-src">{e.src.padEnd(10)}</span>{' '}
      {Object.entries(e.f).map(([k, v]) => (
        <span key={k}><span className="sh-k">{k}=</span><span className="sh-v">{/[\s"]/.test(String(v)) ? `"${String(v).replace(/"/g, "'")}"` : String(v)}</span>{' '}</span>
      ))}
    </button>
  )
}

function ItemView({ it, g, onPin }: { it: Item; g: Game; onPin: (id: string) => void }) {
  const dates = g.def.dates
  if (it.k === 'msg') return <div className={`sh-msg ${it.cls ?? ''}`}>{it.t}</div>
  if (it.k === 'res') return <div className="sh-res">{it.t}</div>
  if (it.mode === 'grid' && it.grid) {
    return (
      <div className="sh-gw"><table className="sh-g"><thead><tr>{it.grid.head.map((h) => <th key={h}>{h}</th>)}</tr></thead>
        <tbody>{it.grid.rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j}>{c}</td>)}</tr>)}</tbody></table></div>
    )
  }
  if (it.mode === 'table') {
    return (
      <div className="sh-gw"><table className="sh-g"><thead><tr>{it.cols.map((c) => <th key={c}>{c}</th>)}</tr></thead>
        <tbody>{it.vis.map((e) => (
          <tr key={e.id} className={`sh-row ${isPinned(g, e.id) ? 'sh-pin' : ''}`} onClick={() => onPin(e.id)}>
            {it.cols.map((c) => <td key={c}>{c === 'time' ? hmsOf(dates, e.ts) : c === 'source' ? e.src : c === 'id' ? e.id : String(e.f[c] ?? '')}</td>)}
          </tr>
        ))}</tbody></table></div>
    )
  }
  return <>{it.vis.map((e) => <EvLine key={e.id} e={e} pinned={isPinned(g, e.id)} onPin={onPin} dates={dates} />)}</>
}

function BlockView({ b, g, onPin }: { b: Block; g: Game; onPin: (id: string) => void }) {
  return (
    <div className="sh-blk">
      <div className="sh-cmdline">› {b.cmd}{b.cost ? <i> +{b.cost} min</i> : null}</div>
      {b.items.map((it, i) => <ItemView key={i} it={it} g={g} onPin={onPin} />)}
      {b.meta && <div className="sh-meta">{b.meta}</div>}
    </div>
  )
}

function FeedbackBox({ facts, note, aiReady }: { facts: string; note: string; aiReady: boolean }) {
  const [fb, setFb] = useState<NoteFeedback | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const ask = () => {
    setBusy(true); setErr('')
    api.shiftFeedback(facts, note).then(setFb).catch((e) => setErr(errText(e))).finally(() => setBusy(false))
  }
  if (note.trim().length < 10) return <div className="tiny muted">No handover note written for this alert.</div>
  return (
    <div>
      {!fb && <button type="button" className="btn" disabled={!aiReady || busy} onClick={ask}>{busy ? 'Reading your note…' : 'Get feedback on my note'}</button>}
      {!aiReady && <div className="tiny muted" style={{ marginTop: 6 }}>Needs Ollama running with a model selected in Settings.</div>}
      {err && <div className="error" role="alert">{err}</div>}
      {fb && (
        <div className="sh-fb">
          {fb.strengths.length > 0 && <><div className="tiny accent mono">WHAT WORKED</div><ul>{fb.strengths.map((s, i) => <li key={i}>{s}</li>)}</ul></>}
          {fb.gaps.length > 0 && <><div className="tiny amber mono">WHAT WAS MISSING OR UNCLEAR</div><ul>{fb.gaps.map((s, i) => <li key={i}>{s}</li>)}</ul></>}
          {fb.tip && <p className="small"><b>Tip:</b> {fb.tip}</p>}
          <div className="tiny muted">Written by your local AI as advice. It does not change your score, and small models can be wrong.</div>
        </div>
      )}
    </div>
  )
}

export function ShiftPage({ aiReady }: { aiReady: boolean }) {
  const [g, setG] = useState<Game | null>(null)
  const [tick, bump] = useState(0)
  const rerender = useCallback(() => bump((n) => n + 1), [])
  const [mode, setMode] = useState<Mode>('training')
  const [results, setResults] = useState<Record<string, ShiftResult>>({})
  const [def, setDef] = useState<ShiftDef>(SHIFTS[0])
  const [vsel, setVsel] = useState<Verdict | null>(null)
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [confirmEnd, setConfirmEnd] = useState(false)
  const [toast, setToast] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [showDebrief, setShowDebrief] = useState(true)
  const cmdRef = useRef<HTMLInputElement | null>(null)
  const outRef = useRef<HTMLDivElement | null>(null)
  const histIdx = useRef(0)

  useEffect(() => { api.shiftResults().then(setResults).catch(() => {}) }, [saved])

  // Show shift toasts one at a time, then clear them.
  useEffect(() => {
    if (!g || !g.toasts.length) return
    const t = g.toasts.shift() as string
    setToast(t)
    const id = window.setTimeout(() => setToast(null), 3200)
    return () => window.clearTimeout(id)
  }, [g, tick])

  // Record the result once, when the shift ends.
  useEffect(() => {
    if (g?.over && !saved) {
      setSaved(true)
      void api.saveShiftResult(g.def.id, total(g, true), maxScore(g)).catch(() => {})
    }
  }, [g?.over, saved, g])

  useEffect(() => { if (outRef.current) outRef.current.scrollTop = outRef.current.scrollHeight }, [tick])

  const start = () => { setG(newGame(mode, def)); setVsel(null); setDraft({}); setSaved(false); setShowDebrief(true); setConfirmEnd(false); rerender() }

  const run = (line: string) => {
    if (!g || !line.trim()) return
    const r = exec(g, line, aiReady)
    rerender()
    if (r.ask) {
      const { persona, turns, slot } = r.ask
      api.shiftChat(persona, turns).then((reply) => {
        slot.t = reply
        g.call?.turns.push({ who: 'persona', text: reply })
      }).catch((e) => { slot.t = `(no answer: ${errText(e)})` }).finally(rerender)
    }
    cmdRef.current?.focus()
  }

  const pin = (id: string) => { if (!g) return; if (!togglePin(g, id)) setToast('Select an alert in the queue first, then pin evidence to it.'); rerender() }
  const wait = (m: number) => { if (!g) return; advance(g, m); rerender() }

  const sel = g?.sel ? alertById(g, g.sel) ?? null : null
  const pins = g && g.sel ? (g.pins[g.sel] ?? []).map((id) => evById(g, id)).filter((e): e is Ev => !!e) : []

  if (!g) {
    const fmt = (t: number) => hmShort(t)
    return (
      <div className="sh-brief">
        <h1 className="h1">SOC shifts</h1>
        <p className="muted" style={{ maxWidth: '70ch' }}>
          A training simulator. You are the only analyst on shift at a fictional company. Nobody will tell you which alerts matter. The rules are noisy, the logs look real, and some of what looks scary is routine.
          Pick a shift. They run from {LEVELS[0]} to {LEVELS[LEVELS.length - 1]}.
        </p>
        <div className="sh-pick" role="radiogroup" aria-label="Choose a shift">
          {SHIFTS.map((d) => {
            const r = results[d.id]
            return (
              <button type="button" key={d.id} role="radio" aria-checked={def.id === d.id} className={`sh-mode ${def.id === d.id ? 'sh-mode-on' : ''}`} onClick={() => setDef(d)}>
                <b>{d.title}</b>
                <span className="tiny mono accent">{d.level.toUpperCase()} · {d.company} · {fmt(d.start)}–{fmt(d.end)} · {d.alerts.filter((a) => !a.late).length}+ alerts</span>
                <span className="small muted">{d.blurb}</span>
                {r && <span className="tiny muted">Best {r.best} of {r.max} · played {r.plays}×</span>}
              </button>
            )
          })}
        </div>
        <div className="panel sh-card">
          <div className="h2">{def.title}</div>
          <p className="small" style={{ maxWidth: '70ch' }}>{def.intro}</p>
          <ul className="small">
            <li>Open an alert, read the raw event, then investigate in the console: write SIEM-style searches, pivot on users, IPs and domains, and look indicators up.</li>
            <li>Every search or lookup costs simulated minutes. Alerts have response deadlines and some things get worse while you work.</li>
            <li>Click log lines to pin evidence, choose a verdict, and write a short handover note. If you declare an incident, contain it with typed commands.</li>
            <li>At the end you get a debrief: what really happened, what you found and missed, and which controls would have prevented it.</li>
          </ul>
          <pre className="sh-cheat">{def.cheat}</pre>
        </div>
        <div className="sh-modes">
          {(['training', 'exam'] as Mode[]).map((m) => (
            <button key={m} type="button" className={`sh-mode ${mode === m ? 'sh-mode-on' : ''}`} onClick={() => setMode(m)} aria-pressed={mode === m}>
              <b>{m === 'training' ? 'Training' : 'Exam'}</b>
              <span className="small muted">{m === 'training' ? 'Live score, hints (-5 each), and an explanation after each decision.' : 'No hints and no feedback until the debrief.'}</span>
            </button>
          ))}
        </div>
        <p className="tiny muted" style={{ maxWidth: '70ch' }}>
          Everything here is simulated. Names, domains and IPs are invented (IPs use documentation ranges). With Ollama running, people you phone are played by your local AI and it can give feedback on your handover notes. Nothing leaves this computer.
        </p>
        <button type="button" className="btn btn-primary" onClick={start}>Start shift at {fmt(def.start)}</button>
      </div>
    )
  }

  const open = openAlerts(g)
  const queue = g.def.alerts.filter((a) => g.arrived.has(a.id)).sort((x, y) => Number(!!g.decided[x.id]) - Number(!!g.decided[y.id]) || (x.at + x.sla) - (y.at + y.sla))
  const incs = g.def.alerts.filter((x) => g.decided[x.id]?.v === 'incident')
  const rawLines = sel ? scenarioLines(g, sel) : []
  const decided = sel ? g.decided[sel.id] : undefined

  const submit = () => {
    if (!sel || !vsel) return
    submitVerdict(g, sel.id, vsel, draft[sel.id] ?? '')
    setVsel(null)
    rerender()
  }

  return (
    <div className="shift">
      <div className="sh-top">
        <div className="mono small muted">{g.def.company.toUpperCase()} · ALL TIMES UTC · {g.mode === 'training' ? 'TRAINING' : 'EXAM'}</div>
        <div className="spacer" />
        <div className="sh-stat"><small>CLOCK</small><span>{hmShort(g.clock)}</span></div>
        <div className="sh-stat"><small>OPEN</small><span>{open.length}</span></div>
        {g.mode === 'training' && <div className="sh-stat"><small>SCORE</small><span>{total(g, false)}</span></div>}
        <button type="button" className="btn" disabled={g.over} onClick={() => wait(5)}>Wait 5 min</button>
        <button type="button" className="btn" disabled={g.over} onClick={() => { if (confirmEnd) { endShift(g); setConfirmEnd(false); rerender() } else { setConfirmEnd(true); window.setTimeout(() => setConfirmEnd(false), 4000) } }}>
          {confirmEnd ? 'Confirm end shift' : 'End shift'}
        </button>
      </div>

      {g.over && !showDebrief && <div className="note">Shift over. <button type="button" className="linkish" onClick={() => setShowDebrief(true)}>Show debrief</button> · <button type="button" className="linkish" onClick={() => { setG(null) }}>Back to start</button></div>}

      <div className="sh-grid">
        <section className="sh-col" aria-label="Alert queue">
          <div className="sh-h"><span>QUEUE</span><span>{open.length} open</span></div>
          {queue.map((a) => {
            const d = g.decided[a.id]
            const left = Math.round((a.at + a.sla - g.clock) / 60)
            return (
              <button type="button" key={a.id} className={`sh-q sh-sev-${a.sev} ${g.sel === a.id ? 'sh-q-on' : ''} ${d ? 'sh-q-done' : ''}`} onClick={() => { g.sel = a.id; setVsel(null); rerender() }}>
                <span className="sh-q-t">{a.title}</span>
                <span className="sh-q-m"><span>{a.id} · {a.ent}</span><span className={left < 0 && !d ? 'red' : ''}>{d ? 'decided' : left < 0 ? 'SLA breached' : `${left} min left`}</span></span>
                <span className="sh-q-m"><span className={`sh-tag sh-tag-${a.sev}`}>{a.sev === 'high' ? 'HIGH' : a.sev === 'med' ? 'MEDIUM' : 'LOW'}</span><span>{hmShort(a.at)} · {a.src}</span></span>
              </button>
            )
          })}
        </section>

        <section className="sh-center" aria-label="Investigation">
          {sel ? (
            <div className="sh-alert">
              <h2 className="h2" style={{ fontSize: 16 }}>{sel.title}</h2>
              <div className="mono tiny muted">{sel.id} · {sel.src} · {sel.ent} · arrived {hmShort(sel.at)}</div>
              <pre className="sh-raw">{rawLines.join('\n') || '(no raw event available)'}</pre>
              <p className="small muted"><b>What the rule saw.</b> {sel.rule}</p>
              <div className="sh-kv">{sel.kv.map((k) => <div key={k[0]} style={{ display: 'contents' }}><span className="muted">{k[0]}</span><span>{k[1]}</span></div>)}</div>
            </div>
          ) : (
            <div className="sh-alert">
              <h2 className="h2" style={{ fontSize: 16 }}>Pick an alert to start</h2>
              <p className="small muted" style={{ maxWidth: '70ch' }}>Severity is only the detection rule's guess. Read the raw event, then investigate in the console. Every search costs shift time, and new alerts keep arriving.</p>
            </div>
          )}
          <div className="sh-out" ref={outRef} aria-live="polite">
            {g.blocks.length ? g.blocks.map((b, i) => <BlockView key={i} b={b} g={g} onPin={pin} />) : <div className="sh-msg">Type <b>help</b> for commands. Example: <b>{g.def.chips[1] ?? 'help'}</b></div>}
          </div>
          <div className="sh-chips">
            {g.def.chips.map((c) => (
              <button type="button" key={c} className="sh-chip" onClick={() => { if (cmdRef.current) { cmdRef.current.value = c; cmdRef.current.focus() } }}>{c.length > 38 ? `${c.slice(0, 36)}…` : c}</button>
            ))}
          </div>
          <div className="sh-in">
            <span className="accent mono">{g.call ? '☎' : '›'}</span>
            <input
              ref={cmdRef}
              className="sh-cmd"
              autoComplete="off"
              spellCheck={false}
              disabled={g.over}
              aria-label="Console"
              placeholder={g.call ? `Speaking to ${g.call.persona}… type your question, or hangup` : 'search, lookup or action…  (Enter to run, ↑ for history)'}
              onKeyDown={(e) => {
                const el = e.currentTarget
                if (e.key === 'Enter') { const v = el.value; el.value = ''; histIdx.current = g.cmdHist.length + 1; run(v) }
                else if (e.key === 'ArrowUp') { if (histIdx.current > 0) { histIdx.current = Math.min(histIdx.current, g.cmdHist.length) - 1; el.value = g.cmdHist[histIdx.current] ?? ''; e.preventDefault() } }
                else if (e.key === 'ArrowDown') { if (histIdx.current < g.cmdHist.length) { histIdx.current++; el.value = g.cmdHist[histIdx.current] ?? ''; e.preventDefault() } }
              }}
            />
          </div>
        </section>

        <section className="sh-col sh-right" aria-label="Evidence and decision">
          {sel ? (
            <>
              <div className="sh-h"><span>EVIDENCE · {sel.id}</span><span>{pins.length} pinned</span></div>
              <div className="sh-card">
                {pins.length ? pins.map((e) => <button type="button" key={e.id} className="sh-pinrow" onClick={() => pin(e.id)} title="Click to unpin">{rawTextOf(g.def.dates, e)}</button>) : <div className="small muted">Click log lines in the console to pin them here. Closing an alert with no evidence is penalised.</div>}
              </div>
              <div className="sh-card">
                <div className="sh-h2">DECISION</div>
                {decided ? (
                  <>
                    <div><span className="sh-tag sh-tag-ok">RECORDED</span> {VLABEL[decided.v]}</div>
                    {g.mode === 'training' && <p className="small muted" style={{ marginTop: 8 }}><b>Best: {VLABEL[sel.best]}.</b> {sel.why}</p>}
                    {g.mode === 'training' && <div style={{ marginTop: 8 }}><FeedbackBox facts={noteFacts(g, sel)} note={decided.note} aiReady={aiReady} /></div>}
                  </>
                ) : (
                  <>
                    <div className="sh-vopts" role="radiogroup" aria-label="Verdict">
                      {VERDICTS.map((v) => (
                        <button type="button" key={v[0]} role="radio" aria-checked={vsel === v[0]} className={`sh-vopt ${vsel === v[0] ? 'sh-vopt-on' : ''}`} onClick={() => setVsel(v[0])}>{v[1]}</button>
                      ))}
                    </div>
                    <textarea className="sh-note" aria-label="Handover note" placeholder="Handover note: what happened, what you found, what should happen next" value={draft[sel.id] ?? ''} onChange={(e) => setDraft((d) => ({ ...d, [sel.id]: e.target.value }))} />
                    <button type="button" className="btn btn-primary" style={{ marginTop: 8, width: '100%' }} disabled={!vsel || g.over} onClick={submit}>Submit decision</button>
                  </>
                )}
              </div>
            </>
          ) : <div className="sh-card small muted">Select an alert to pin evidence and decide.</div>}

          <div className="sh-h"><span>INCIDENT BOARD</span><span className={`sh-tag ${incs.length ? 'sh-tag-high' : ''}`}>{incs.length ? 'INC-1 OPEN' : 'NONE DECLARED'}</span></div>
          {incs.length ? (
            <div className="sh-card sh-inc">
              <div className="sh-h2 red">INC-1 · LINKED ALERTS</div>
              {incs.map((x) => <div className="small" key={x.id}>{x.id} · {x.title}</div>)}
              <p className="small muted" style={{ marginTop: 8 }}>Declaring an incident does not contain anything. Run your containment actions in the console. Type <b>help</b> for the list.</p>
            </div>
          ) : <div className="sh-card small muted">Escalate an alert as an incident to open the response board. Containment commands work any time, but until you declare, there is no incident to respond to.</div>}
          <div className="sh-card"><div className="sh-h2">ACTIONS TAKEN</div>{g.actions.size ? [...g.actions].map((a) => <div className="sh-log" key={a}>{a}</div>) : <div className="small muted">None yet.</div>}</div>
          <div className="sh-h"><span>SHIFT LOG</span><span /></div>
          <div className="sh-card">{g.log.slice(0, 14).map((l, i) => <div className="sh-log" key={i}><b>{hmShort(l.t)}</b> {l.m}</div>)}</div>
        </section>
      </div>

      {toast && <div className="sh-toast" role="status">{toast}</div>}
      {g.over && showDebrief && <Debrief g={g} aiReady={aiReady} onClose={() => setShowDebrief(false)} onAgain={() => { setG(null) }} />}
    </div>
  )
}

function scenarioLines(g: Game, a: Alert): string[] {
  const lines = scn(g).events.filter((e) => e.tag === a.raw && visible(g, e))
  const text = (e: Ev) => rawTextOf(g.def.dates, e)
  const out = lines.length > 4 ? [...lines.slice(0, 3).map(text), `   ... ${lines.length - 4} more events, same pattern ...`, text(lines[lines.length - 1])] : lines.map(text)
  if (a.rawNote) out.push(a.rawNote)
  return out
}

function Debrief({ g, aiReady, onClose, onAgain }: { g: Game; aiReady: boolean; onClose: () => void; onAgain: () => void }) {
  const tot = total(g, true)
  const max = maxScore(g)
  const pct = Math.max(0, Math.round((100 * tot) / max))
  const grade = pct >= 85 ? 'Strong shift' : pct >= 60 ? 'Solid, with gaps' : pct >= 30 ? 'Needs work' : 'Rough shift'
  const gc = gradeContain(g)
  const rows = g.def.alerts.filter((a) => !(a.late && !g.flags[a.late]))
  return (
    <div className="sh-overlay" role="dialog" aria-label="Shift debrief">
      <div className="sh-sheet">
        <div className="mono tiny accent">SHIFT DEBRIEF</div>
        <h2 className="h1" style={{ marginTop: 4 }}>{grade}: {tot} points ({pct}% of {max} available)</h2>
        <p className="small muted">{g.def.triggers.map((t) => t.note(!!g.flagDone[t.flag], !!g.flags[t.flag])).join(' ')} Hints used: {g.hints}.</p>

        <div className="sh-h2">WHAT ACTUALLY HAPPENED</div>
        <div className="sh-tl">
          {timeline(g).map((t) => (
            <div key={t.at}><span className="mono tiny muted">{hmShort(t.at)} UTC</span> <b>{t.text}</b><br />
              <span className="small muted">{t.ttp} · <span className={t.found ? 'accent' : 'red'}>{t.found ? 'you found this' : 'you missed this'}</span></span></div>
          ))}
        </div>

        <div className="sh-h2">CONTAINMENT</div>
        <div className="sh-two">
          <div>{gc.items.map((i) => <div className="small" key={i.label}><span className={i.done ? 'accent' : 'red'}>{i.done ? '✓' : '✗'}</span> {i.label} <span className="mono">({i.done ? '+' : ''}{i.pts})</span></div>)}</div>
          <div>{gc.bad.length ? gc.bad.map((w) => <div className="small red" key={w.label}>✗ {w.label} ({w.pts})</div>) : <div className="small accent">No harmful actions taken.</div>}{g.def.triggers.filter((t) => g.flags[t.flag]).map((t) => <div className="small red" key={t.flag}>✗ {t.penaltyLabel} (-{t.penalty})</div>)}</div>
        </div>

        <div className="sh-h2">GAPS THAT LET IT HAPPEN</div>
        <ul className="small muted">{g.def.gaps.map((x) => <li key={x}>{x}</li>)}</ul>

        <div className="sh-h2">ALERT BY ALERT</div>
        <div className="sh-gw">
          <table className="sh-d">
            <thead><tr><th>ALERT</th><th>YOU</th><th>BEST</th><th>EVIDENCE</th><th>PTS</th><th>WHY</th></tr></thead>
            <tbody>
              {rows.map((a) => {
                const gr = gradeAlert(g, a)
                const d = g.decided[a.id]
                return (
                  <tr key={a.id}>
                    <td>{a.title}<br /><span className="tiny muted mono">{a.id} · {a.ent}</span></td>
                    <td className={d && d.v === a.best ? 'accent' : 'red'}>{d ? VLABEL[d.v] : 'Not handled'}</td>
                    <td>{VLABEL[a.best]}</td>
                    <td className="small">{a.req.map((r) => <div key={r}><span className={reqMet(g, r) ? 'accent' : 'red'}>{reqMet(g, r) ? '✓' : '✗'}</span> {g.def.evd[r]}</div>)}</td>
                    <td className={`mono ${gr.pts >= 0 ? 'accent' : 'red'}`}>{gr.pts > 0 ? '+' : ''}{gr.pts}</td>
                    <td className="small">{a.why}{gr.notes.length ? <><br /><b>{gr.notes.join(', ')}</b></> : null}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {rows.some((a) => (g.decided[a.id]?.note ?? '').trim().length >= 10) && (
          <>
            <div className="sh-h2">YOUR HANDOVER NOTES</div>
            {rows.filter((a) => (g.decided[a.id]?.note ?? '').trim().length >= 10).map((a) => (
              <div key={a.id} className="sh-card" style={{ margin: '0 0 10px' }}>
                <div className="mono tiny muted">{a.id} · {a.title}</div>
                <p className="small" style={{ whiteSpace: 'pre-wrap' }}>{g.decided[a.id]?.note}</p>
                <FeedbackBox facts={noteFacts(g, a)} note={g.decided[a.id]?.note ?? ''} aiReady={aiReady} />
              </div>
            ))}
          </>
        )}

        <div className="sh-actions">
          <button type="button" className="btn btn-primary" onClick={onAgain}>Play again</button>
          <button type="button" className="btn" onClick={onClose}>Close debrief</button>
        </div>
      </div>
    </div>
  )
}

