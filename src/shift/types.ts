// Types shared by every shift. A shift is plain data (a ShiftDef): the engine,
// the page and the tests all read the active definition, so adding a shift
// means adding one file in shifts/ and listing it in index.ts.
export type Src = string
export type Val = string | number
export interface Ev {
  id: string
  src: Src
  ts: number // seconds from today 00:00 UTC; yesterday is negative
  f: Record<string, Val>
  key?: string
  tag?: string
  cond?: string // only exists once this flag has been set by a trigger
}
export type Sev = 'low' | 'med' | 'high'
export type Verdict = 'incident' | 'fp' | 'benign' | 'it' | 'insider'
export interface Alert {
  id: string
  title: string
  sev: Sev
  src: string
  ent: string
  at: number
  sla: number
  raw: string
  rawNote?: string
  rule: string
  kv: [string, string][]
  best: Verdict
  alt: Partial<Record<Verdict, number>>
  req: string[]
  why: string
  hints: string[]
  late?: string // only arrives if this trigger flag was set
}
export interface User { n: string; host: string; dept: string; dev: string; ip: string }
export interface Scenario { events: Ev[]; byKey: Record<string, Ev> }
export type Level = 'Starter' | 'Easy' | 'Medium' | 'Hard' | 'Expert'

// Minimal view of the game that triggers and checks need (avoids a cycle).
export interface GameView {
  actions: Set<string>
  hist: string[]
  flags: Record<string, boolean>
  clock: number
}
export interface Trigger {
  flag: string
  at: number // checked once, when the clock reaches this time
  contained: (g: GameView) => boolean
  penalty: number
  penaltyLabel: string
  okLog: string
  note: (done: boolean, happened: boolean) => string // debrief sentence
}
export interface Containment { label: string; pts: number; t: (g: GameView) => boolean; when?: (g: GameView) => boolean }
export interface Wrong { label: string; pts: number; t: (g: GameView) => boolean }
export interface TimelineRow { at: number; text: string; ttp: string; found: boolean }

export interface Intel {
  ti: Record<string, string>
  tiRules?: [RegExp, string][]
  whois: Record<string, string>
  phone: Record<string, string>
  badge: Record<string, string>
  hr: Record<string, string>
  tickets: Record<string, string>
  askIt: (q: string) => string
  protectedIps?: Record<string, string> // blocking these causes an outage
  phoneBusy?: (user: string, clock: number) => string | null
}

export interface ShiftDef {
  id: string
  title: string
  company: string
  level: Level
  blurb: string
  intro: string // briefing paragraph
  start: number
  end: number
  dates: [string, string] // yesterday, today (display only)
  fields: Record<string, string>
  srcdesc: Record<string, string>
  users: User[]
  build: () => Scenario
  alerts: Alert[]
  evd: Record<string, string>
  intel: Intel
  callable: string[]
  triggers: Trigger[]
  contain: Containment[]
  wrong: Wrong[]
  checks: Record<string, (g: GameView) => boolean>
  timeline: (k: Set<string>, g: GameView) => TimelineRow[]
  gaps: string[]
  noteTail: (a: Alert) => string
  chips: string[]
  cheat: string
  // Scripted perfect play, used by the tests to prove each shift is solvable.
  solution: { cmds: string[]; verdicts: [string, Verdict][]; pins: Record<string, string[]> }
}
