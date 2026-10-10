import { useEffect, useState } from 'react'
import { animationsOn, reducedMotion } from './prefs'
import { api, errText } from './api'
import { FACTS, factForDay } from './facts'

/** Counts up to `to` once when shown. Shows the final number straight away if motion is off. */
export function CountUp({ to, ms = 900 }: { to: number; ms?: number }) {
  const still = !animationsOn() || reducedMotion()
  const [v, setV] = useState(still ? to : 0)
  useEffect(() => {
    if (!animationsOn() || reducedMotion()) { setV(to); return }
    let raf = 0
    const t0 = performance.now()
    const tick = (t: number) => {
      const p = Math.min(1, (t - t0) / ms)
      setV(Math.round(to * (1 - Math.pow(1 - p, 3))))
      if (p < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [to, ms])
  return <>{v}</>
}

/** Semicircle gauge: green, amber, red zones and a needle that swings to the value. */
export function Gauge({ value, max = 20, label }: { value: number; max?: number; label: string }) {
  const frac = Math.min(1, Math.max(0, value / max))
  const angle = -90 + frac * 180
  const arc = (a0: number, a1: number) => {
    const p = (a: number) => [60 + 46 * Math.cos((Math.PI * (180 + a)) / 180), 62 + 46 * Math.sin((Math.PI * (180 + a)) / 180)]
    const [x0, y0] = p(a0)
    const [x1, y1] = p(a1)
    return `M${x0.toFixed(1)} ${y0.toFixed(1)} A46 46 0 0 1 ${x1.toFixed(1)} ${y1.toFixed(1)}`
  }
  return (
    <svg viewBox="0 0 120 72" className="gauge" role="img" aria-label={`Threat temperature ${label}`}>
      <path d={arc(0, 36)} className="gauge-calm" />
      <path d={arc(36, 108)} className="gauge-mid" />
      <path d={arc(108, 180)} className="gauge-high" />
      <g className="gauge-needle" style={{ transform: `rotate(${angle}deg)`, transformOrigin: '60px 62px' }}>
        <line x1="60" y1="62" x2="60" y2="22" />
      </g>
      <circle cx="60" cy="62" r="4" className="gauge-hub" />
    </svg>
  )
}

/** Audio bars shown while the brief is being read aloud. */
export function Wave() {
  return (
    <span className="wave" aria-hidden="true">
      {[0, 1, 2, 3, 4, 5].map((i) => <span key={i} className="wave-bar" style={{ animationDelay: `${i * 0.12}s` }} />)}
    </span>
  )
}

/** A radar dial with a sweeping beam. */
export function Radar() {
  return <span className="radar" aria-hidden="true" />
}

/** A security fun fact: one vetted fact per day. "Another one" can also show AI-written ones, clearly labelled. */
export function FunFact({ className = 'panel' }: { className?: string }) {
  const [shift, setShift] = useState(0)
  const [ai, setAi] = useState<{ tag: string; text: string }[]>([])
  const [canAi, setCanAi] = useState(false)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  useEffect(() => {
    api.aiFacts().then(setAi).catch(() => setAi([]))
    api.aiStatus().then((s) => setCanAi(s.running && s.enabled)).catch(() => setCanAi(false))
  }, [])
  const built = factForDay(new Date(), 0)
  // Day 0 is always a vetted built-in fact. After that, "Another one" mixes in AI-written ones.
  const pool = [...FACTS.map((f) => ({ ...f, ai: false })), ...ai.map((f) => ({ ...f, ai: true }))]
  const f = shift === 0 ? { ...built, ai: false } : pool[(FACTS.indexOf(built) + shift * 7) % pool.length]
  const more = () => {
    setBusy(true)
    setMsg('')
    api.makeFacts().then((l) => { setAi(l); setMsg(`Added. ${l.length} AI-written facts saved.`) }).catch((e) => setMsg(errText(e))).finally(() => setBusy(false))
  }
  return (
    <section className={className}>
      <div className="panel-row mono small"><span className="muted">SECURITY FUN FACT</span><span className={`tag ${f.ai ? 'tag-amber' : 'tag-grey'}`}>{f.ai ? `AI · ${f.tag}` : f.tag}</span></div>
      <div key={shift} className="small fact-text">{f.text}</div>
      {f.ai && <div className="tiny muted">Written by your local AI. Small models can be wrong, so check before you quote it.</div>}
      <div className="panel-row">
        <button type="button" className="linkish small" onClick={() => setShift((n) => n + 1)}>Another one →</button>
        {canAi && <button type="button" className="linkish small" disabled={busy} onClick={more}>{busy ? 'Writing…' : 'Make more with AI'}</button>}
      </div>
      {msg && <div className="tiny muted">{msg}</div>}
    </section>
  )
}

/** Ticking UTC clock for the top bar. */
export function LiveClock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
  return <span className="mono small clock" aria-label="Current time, UTC">UTC {now.toISOString().slice(11, 19)}</span>
}

/** A heartbeat line that scrolls along, to show the app is live. */
export function Pulse() {
  const beat = 'M0 12 H18 L22 12 L26 3 L31 21 L35 12 H60'
  return (
    <svg className="pulse" viewBox="0 0 240 24" preserveAspectRatio="none" aria-hidden="true">
      <g className="pulse-run">
        {[0, 60, 120, 180, 240, 300].map((x) => <path key={x} d={beat} transform={`translate(${x} 0)`} />)}
      </g>
    </svg>
  )
}
