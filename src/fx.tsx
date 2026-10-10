import { useEffect, useState } from 'react'
import { animationsOn, reducedMotion } from './prefs'

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
