// Helpers shared by the shift files: a seeded random generator (so every play
// of a shift is identical) and a small event builder.
import type { Ev, Scenario, Src, User, Val } from './types'

export const hm = (h: number, m: number, s = 0): number => h * 3600 + m * 60 + s
export const m = (n: number): number => n * 60

export function mulberry(seed: number): () => number {
  let a = seed | 0
  return () => {
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export interface Gen {
  R: () => number
  pick: <T>(a: T[]) => T
  ri: (a: number, b: number) => number
  ev: (src: Src, ts: number, f: Record<string, Val>, o?: { key?: string; tag?: string; cond?: string }) => void
}

// Build a scenario: `fn` adds events with G.ev(); we sort them, number them
// and index the ones that carry a key.
export function makeScenario(seed: number, fn: (G: Gen) => void): Scenario {
  const R = mulberry(seed)
  const EV: Omit<Ev, 'id'>[] = []
  const G: Gen = {
    R,
    pick: <T,>(a: T[]): T => a[Math.floor(R() * a.length)],
    ri: (a, b) => a + Math.floor(R() * (b - a + 1)),
    ev: (src, ts, f, o = {}) => { EV.push({ src, ts, f, key: o.key, tag: o.tag, cond: o.cond }) },
  }
  fn(G)
  EV.sort((a, b) => a.ts - b.ts)
  const events: Ev[] = EV.map((e, i) => ({ ...e, id: `E${1000 + i}` }))
  const byKey: Record<string, Ev> = {}
  for (const e of events) if (e.key) byKey[e.key] = e
  return { events, byKey }
}

export function mkUsers(rows: [string, string, string, string][], net = 10, sub = 20): User[] {
  return rows.map((a, i) => ({ n: a[0], host: a[1], dept: a[2], dev: a[3], ip: `${net}.${sub + (i % 200)}.${10 + (i % 90)}.${20 + i * 3}` }))
}

export function memo<T>(f: () => T): () => T {
  let c: T | null = null
  return () => (c ??= f())
}

export function b64utf16(s: string): string {
  let bin = ''
  for (const ch of s) { const c = ch.charCodeAt(0); bin += String.fromCharCode(c & 255, c >> 8) }
  return btoa(bin)
}

// Loop over yesterday (full working day) and today (up to `endToday`) for each user.
export function eachDay(users: User[], endToday: number, fn: (u: User, base: number, end: number, day: number) => void): void {
  for (const d of [-1, 0]) for (const u of users) fn(u, d * 86400, d < 0 ? hm(17, 30) : endToday, d)
}

// Did the analyst run a command matching this pattern? (used by the c_ checks)
export const did = (g: { hist: string[] }, re: RegExp): boolean => g.hist.some((h) => re.test(h))
// Has every one of these containment actions been taken? Keys are lower-case, as the engine records them.
export const acted = (g: { actions: Set<string> }, ...keys: string[]): boolean => keys.every((k) => g.actions.has(k))
export const anyActed = (g: { actions: Set<string> }, ...keys: string[]): boolean => keys.some((k) => g.actions.has(k))

export function defaultNoteTail(a: { best: string }): string {
  return a.best === 'incident'
    ? 'It should also say what was contained and what still needs doing.'
    : 'It should say why nothing needs escalating, or who it was handed to.'
}
