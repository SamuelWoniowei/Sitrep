// Checks that apply to every shift in the catalogue, so a new shift file is
// held to the same bar: unique ids, resolvable keys, only documentation IPs,
// a scripted perfect run that scores well, and doing nothing that scores badly.
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { SHIFTS, LEVELS } from '../shift/index'
import { advance, exec, gradeAlert, gradeContain, gradeTicket, maxScore, newGame, submitVerdict, togglePin, total, trueSev, ticketStatus, type Game } from '../shift/engine'
import type { ShiftDef } from '../shift/types'

const DOC_IP = /^(203\.0\.113\.|198\.51\.100\.|192\.0\.2\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|82\.31\.14\.9$|49\.36\.140\.22$|127\.)/

function perfect(def: ShiftDef): Game {
  const g = newGame('exam', def)
  const sc = def.build()
  const todo = new Map(def.solution.verdicts)
  const decide = () => {
    for (const a of def.alerts) {
      if (!g.arrived.has(a.id) || g.decided[a.id] || !todo.has(a.id)) continue
      g.sel = a.id
      exec(g, `claim ${a.id}`, false)
      for (const k of def.solution.pins[a.id] ?? []) { const e = sc.byKey[k]; if (e) togglePin(g, e.id) }
      const h = 'Handover: what happened, what I found and what happens next.'
      submitVerdict(g, a.id, todo.get(a.id)!, h, { sev: trueSev(a), esc: { summary: h, who: h, when: h, actions: h } })
    }
  }
  decide()
  for (const c of def.solution.cmds) { exec(g, c, false); decide() }
  while (!g.over && g.clock < def.end - 60) { advance(g, 1); decide() }
  g.sel = null
  return g
}

describe('catalogue', () => {
  it('has ten shifts across all five levels, easiest first, with unique ids', () => {
    expect(SHIFTS).toHaveLength(10)
    expect(new Set(SHIFTS.map((s) => s.id)).size).toBe(10)
    const idx = SHIFTS.map((s) => LEVELS.indexOf(s.level))
    expect([...idx].sort((a, b) => a - b)).toEqual(idx)
    for (const l of LEVELS) expect(SHIFTS.some((s) => s.level === l), l).toBe(true)
  })
})

describe.each(SHIFTS.map((s) => [s.id, s] as const))('%s', (_id, def) => {
  const sc = def.build()
  it('has a coherent scenario', () => {
    expect(new Set(sc.events.map((e) => e.id)).size).toBe(sc.events.length)
    expect(sc.events.length).toBeGreaterThan(300)
    const srcs = new Set(sc.events.map((e) => e.src))
    for (const s of srcs) expect(def.fields[s], `source ${s} has no field list`).toBeTruthy()
    for (const e of sc.events) for (const k of Object.keys(e.f)) expect(def.fields[e.src].split(' ').includes(k), `${e.src}.${k}`).toBe(true)
    for (const e of sc.events) { const ip = String(e.f.ip ?? ''); if (ip) expect(DOC_IP.test(ip), ip).toBe(true) }
  })
  it('wires alerts, evidence and tags together', () => {
    const ids = def.alerts.map((a) => a.id)
    expect(new Set(ids).size).toBe(ids.length)
    for (const a of def.alerts) {
      expect(sc.events.some((e) => e.tag === a.raw), `${a.id} raw tag ${a.raw}`).toBe(true)
      expect(a.hints.length, a.id).toBeGreaterThan(0)
      expect(a.sla).toBeGreaterThan(0)
      for (const r of a.req) {
        expect(def.evd[r], `${a.id} requirement ${r} has no description`).toBeTruthy()
        if (r.startsWith('c_')) expect(def.checks[r], `check ${r}`).toBeTypeOf('function')
        else expect(sc.byKey[r], `evidence key ${r}`).toBeTruthy()
      }
      if (a.late) expect(def.triggers.some((t) => t.flag === a.late), `${a.id} late flag`).toBe(true)
    }
    for (const e of sc.events) if (e.cond) expect(def.triggers.some((t) => t.flag === e.cond), `event cond ${e.cond}`).toBe(true)
    expect(def.alerts.filter((a) => a.best === 'incident' || a.best === 'insider').length).toBeGreaterThan(0)
    expect(def.alerts.some((a) => a.best !== 'incident')).toBe(true)
    for (const [id] of def.solution.verdicts) expect(ids).toContain(id)
  })
  it('only lets you phone people it can play', () => {
    for (const p of def.callable) expect(def.intel.phone[p] ?? def.users.find((u) => u.n === p), p).toBeTruthy()
  })
  it('a scripted perfect run gets every call right and a high score', () => {
    const g = perfect(def)
    for (const [id, v] of def.solution.verdicts) expect(g.decided[id]?.v, id).toBe(v)
    for (const a of def.alerts) if (!(a.late && !g.flags[a.late])) expect(g.decided[a.id]?.v ?? 'none', a.id).toBe(a.best)
    expect(gradeContain(g).bad, 'perfect play should do nothing harmful').toEqual([])
    for (const t of def.triggers) expect(g.flags[t.flag], `trigger ${t.flag} should be prevented`).toBe(false)
    const pct = total(g, true) / maxScore(g)
    expect(pct).toBeGreaterThan(0.85)
    for (const a of def.alerts) if (g.decided[a.id]) expect(gradeAlert(g, a).miss, `${a.id} evidence`).toEqual([])
  })
  it('runs the ticket workflow: claim, work notes, severity, escalation handover', () => {
    const g = newGame('exam', def)
    const first = def.alerts.find((a) => g.arrived.has(a.id))!
    const tk = g.tickets[first.id]
    expect(tk.num).toMatch(/^TKT-\d+$/)
    expect(ticketStatus(g, first.id)).toBe('New')
    exec(g, 'note too early', false)
    expect(tk.notes).toHaveLength(0)
    const t0 = g.clock
    exec(g, `claim ${first.id}`, false)
    expect(g.clock - t0).toBe(60)
    expect(ticketStatus(g, first.id)).toBe('In progress')
    exec(g, 'note checking the sign-in history', false)
    expect(tk.notes).toHaveLength(1)
    exec(g, `claim ${first.id}`, false)
    expect(tk.trail.filter((x) => x.m.startsWith('Claimed'))).toHaveLength(1)
    const best = first.best
    const esc = best === 'incident' || best === 'insider'
    submitVerdict(g, first.id, best, 'x', { sev: trueSev(first), esc: { summary: 'short', who: 'short', when: 'short', actions: 'short' } })
    expect(ticketStatus(g, first.id)).toBe(esc ? 'Escalated' : best === 'it' ? 'Transferred' : 'Closed')
    if (esc) expect(gradeTicket(g, first).escOk).toBe(0)
  })
  it('penalises a late acknowledgement and rewards a complete handover', () => {
    const late = newGame('exam', def)
    const a = def.alerts.find((x) => late.arrived.has(x.id))!
    advance(late, 50)
    exec(late, `claim ${a.id}`, false)
    expect(gradeTicket(late, a).pts).toBe(-10)
    const g = newGame('exam', def)
    const e = def.alerts.find((x) => (x.best === 'incident' || x.best === 'insider') && g.arrived.has(x.id))
    if (!e) return
    exec(g, `claim ${e.id}`, false)
    const f = 'Compromised account used from a foreign address to send mail'
    submitVerdict(g, e.id, e.best, '', { sev: 'high', esc: { summary: f, who: f, when: f, actions: f } })
    expect(gradeTicket(g, e)).toMatchObject({ pts: 30, escOk: 4 })
    const h = newGame('exam', def)
    exec(h, `claim ${e.id}`, false)
    submitVerdict(h, e.id, e.best, '', { sev: 'high' })
    expect(gradeTicket(h, e).pts).toBe(-10)
  })
  it('limits work in progress to three tickets', () => {
    const g = newGame('exam', def)
    const ids = def.alerts.filter((a) => g.arrived.has(a.id)).map((a) => a.id)
    for (const id of ids) exec(g, `claim ${id}`, false)
    expect(Object.values(g.tickets).filter((t) => t.owner).length).toBe(Math.min(3, ids.length))
  })
  it('doing nothing is a clear failure', () => {
    const g = newGame('exam', def)
    advance(g, 600)
    expect(g.over).toBe(true)
    expect(total(g, true)).toBeLessThan(0)
  })
  it('allowing the triggers to fire scores worse than preventing them', () => {
    if (!def.triggers.length) return
    const good = perfect(def)
    const idle = newGame('exam', def)
    advance(idle, 600)
    for (const t of def.triggers) expect(idle.flags[t.flag], t.flag).toBe(true)
    expect(total(idle, true)).toBeLessThan(total(good, true))
  })
  it('blanket strategies fail: escalate everything, or close everything', () => {
    const best = total(perfect(def), true)
    for (const v of ['incident', 'benign'] as const) {
      const g = newGame('exam', def)
      for (let i = 0; i < 120 && !g.over; i++) {
        advance(g, 1)
        for (const a of def.alerts) if (g.arrived.has(a.id) && !g.decided[a.id]) submitVerdict(g, a.id, v, 'x')
      }
      expect(total(g, true), v).toBeLessThan(best * 0.5)
    }
  })
})

describe('Rust side stays in step with the catalogue', () => {
  const ai = readFileSync('src-tauri/src/ai.rs', 'utf8')
  const cmds = readFileSync('src-tauri/src/commands.rs', 'utf8')
  it('knows every shift id, so results can be saved', () => {
    const block = cmds.match(/const SHIFT_IDS: &\[&str\] = &\[([\s\S]*?)\];/)![1]
    const ids = [...block.matchAll(/"([^"]+)"/g)].map((m) => m[1])
    expect(ids.sort()).toEqual(SHIFTS.map((s) => s.id).sort())
  })
  it('has a character for everyone you can phone, and no duplicates', () => {
    const personas = [...ai.matchAll(/^\s{8}id: "([^"]+)",/gm)].map((m) => m[1])
    expect(new Set(personas).size).toBe(personas.length)
    for (const s of SHIFTS) for (const c of s.callable) expect(personas, `${s.id}: ${c}`).toContain(c)
  })
})
