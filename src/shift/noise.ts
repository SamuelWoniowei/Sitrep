// Extra "noise" alerts layered on top of a shift. Real queues are mostly routine
// alerts that need a quick, evidence-backed look, so every shift gets a handful
// on top of its main story. Each spec supplies the alert, the log lines that
// prove what it was, and any lookups (ask-it, ticket, hr, phone) that settle it.
// The base shift files stay untouched; index.ts wraps them with withNoise().
import { memo } from './common'
import type { Alert, Ev, Sev, ShiftDef, Val, Verdict } from './types'

export interface NoiseEvent { src: string; t: number; f: Record<string, Val> }
export interface Noise {
  id: string
  title: string
  sev: Sev
  src: string // shown in the queue ("Web proxy", "EDR" ...)
  ent: string
  at: number
  sla: number
  rule: string
  kv: [string, string][]
  best: Verdict
  alt?: Partial<Record<Verdict, number>>
  why: string
  hints: string[]
  evText: string
  events: NoiseEvent[] // the first one is the key evidence and is shown as the raw event
  ask?: [RegExp, string]
  ticket?: [string, string]
  hr?: [string, string]
  phone?: [string, string]
  ti?: [string, string]
}

const keyOf = (n: Noise): string => `n_${n.id}`

export function withNoise(def: ShiftDef, specs: Noise[]): ShiftDef {
  const base = def.build
  const build = memo(() => {
    const sc = base()
    const extra: Ev[] = []
    for (const n of specs) {
      n.events.forEach((e, i) => {
        extra.push({ id: `N${n.id}_${i}`, src: e.src, ts: e.t, f: e.f, key: i === 0 ? keyOf(n) : undefined, tag: i === 0 ? `${n.id}raw` : undefined })
      })
    }
    const events = [...sc.events, ...extra].sort((a, b) => a.ts - b.ts)
    const byKey: Record<string, Ev> = { ...sc.byKey }
    for (const e of extra) if (e.key) byKey[e.key] = e
    return { events, byKey }
  })
  const alerts: Alert[] = specs.map((n) => ({
    id: n.id, title: n.title, sev: n.sev, src: n.src, ent: n.ent, at: n.at, sla: n.sla, raw: `${n.id}raw`, rule: n.rule, kv: n.kv,
    best: n.best, alt: n.alt ?? {}, req: [keyOf(n)], why: n.why, hints: n.hints,
  }))
  const evd = { ...def.evd, ...Object.fromEntries(specs.map((n) => [keyOf(n), n.evText])) }
  const asks = specs.filter((n) => n.ask).map((n) => n.ask as [RegExp, string])
  const intel = {
    ...def.intel,
    ti: { ...def.intel.ti, ...Object.fromEntries(specs.filter((n) => n.ti).map((n) => n.ti as [string, string])) },
    tickets: { ...def.intel.tickets, ...Object.fromEntries(specs.filter((n) => n.ticket).map((n) => n.ticket as [string, string])) },
    hr: { ...def.intel.hr, ...Object.fromEntries(specs.filter((n) => n.hr).map((n) => n.hr as [string, string])) },
    phone: { ...def.intel.phone, ...Object.fromEntries(specs.filter((n) => n.phone).map((n) => n.phone as [string, string])) },
    askIt: (q: string) => {
      for (const [re, a] of asks) if (re.test(q)) return a
      return def.intel.askIt(q)
    },
  }
  return {
    ...def,
    build, alerts: [...def.alerts, ...alerts], evd, intel,
    solution: {
      ...def.solution,
      verdicts: [...def.solution.verdicts, ...specs.map((n) => [n.id, n.best] as [string, Verdict])],
      pins: { ...def.solution.pins, ...Object.fromEntries(specs.map((n) => [n.id, [keyOf(n)]])) },
    },
  }
}
