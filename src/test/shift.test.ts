import { describe, expect, it } from 'vitest'
import { ATT, PHD, shift1 } from '../shift/shifts/s01'
import { hm } from '../shift/common'
import { advance, b64dec, exec, gradeAlert, gradeContain, maxScore, newGame, openAlerts, runQuery, submitVerdict, tiLookup, togglePin, total, type Game } from '../shift/engine'

const run = (g: Game, l: string, ai = false) => exec(g, l, ai)
const rowsOf = (g: Game, q: string) => runQuery(g, q)

describe('shift data', () => {
  it('has unique event ids, every key resolves, and the attack chain is in order', () => {
    const { events, byKey } = shift1.build()
    expect(new Set(events.map((e) => e.id)).size).toBe(events.length)
    expect(events.length).toBeGreaterThan(2000)
    for (const k of ['e_post', 'e_rule', 'e_success_foreign', 'e_bec', 'e_da', 'e_ps']) expect(byKey[k]).toBeTruthy()
    expect(byKey.e_post.ts).toBeLessThan(byKey.e_success_foreign.ts)
    expect(byKey.e_success_foreign.ts).toBeLessThan(byKey.e_rule.ts)
  })
  it('only uses documentation IP ranges for outside addresses', () => {
    const { events } = shift1.build()
    const ips = new Set(events.map((e) => String(e.f.ip ?? '')).filter(Boolean))
    for (const ip of ips) expect(/^(203\.0\.113\.|198\.51\.100\.|192\.0\.2\.|82\.31\.14\.9|49\.36\.140\.22)/.test(ip), ip).toBe(true)
  })
})

describe('query language', () => {
  it('filters by field, wildcard and negation, and hides the future', () => {
    const g = newGame('training', shift1)
    expect(rowsOf(g, 'source=entra user=jenna.hart result=success').rows.every((e) => e.f.user === 'jenna.hart')).toBe(true)
    expect(rowsOf(g, 'source=entra user!=jenna.hart user=*cole').rows.every((e) => e.f.user === 'david.cole')).toBe(true)
  })
  it('sees events once the clock passes them', () => {
    const g = newGame('training', shift1)
    // At 08:30 the attacker events (08:03-08:22) are already in the past.
    expect(rowsOf(g, `source=entra ip=${ATT}`).total).toBe(12)
    expect(rowsOf(g, 'source=ad op=*Domain Admins*').total).toBe(0)
    advance(g, 80)
    expect(rowsOf(g, 'source=ad op="Member added to Domain Admins"').total).toBe(1)
  })
  it('supports pipes: stats, top, table, sort, head, dedup', () => {
    const g = newGame('training', shift1)
    const s = rowsOf(g, `source=proxy domain=*micros0ft* | stats count by user`)
    expect(s.mode).toBe('grid')
    expect(s.grid?.rows[0]).toEqual(['jenna.hart', 2])
    expect(rowsOf(g, 'source=mail subj=Remittance* | top sender').grid?.rows[0]).toEqual(['remit@brightpath-pay.co', 10])
    const t = rowsOf(g, 'source=entra user=jenna.hart | sort -time | head 3 | table time,ip')
    expect(t.rows).toHaveLength(3)
    expect(t.cols).toEqual(['time', 'ip'])
    expect(t.rows[0].ts).toBeGreaterThanOrEqual(t.rows[1].ts)
    expect(rowsOf(g, 'source=vpn | dedup user | head 50').rows.length).toBeLessThanOrEqual(14)
    expect(rowsOf(g, 'source=proxy | explode').err).toMatch(/Unknown pipe/)
  })
  it('numeric comparison and quoted values work, and odd input never throws', () => {
    const g = newGame('training', shift1)
    expect(rowsOf(g, 'source=proxy bytes_out=412 method=POST').total).toBe(1)
    expect(rowsOf(g, 'source=proxy bytes_out>6000').rows.every((e) => Number(e.f.bytes_out) > 6000)).toBe(true)
    expect(rowsOf(g, 'source=exchange detail="*ForwardTo*"').total).toBe(1)
    for (const q of ['(((', 'source=', '| |', '*', 'user=[a-z', '"unterminated', 'earliest=zz']) expect(() => rowsOf(g, q)).not.toThrow()
  })
})

describe('lookups and commands', () => {
  it('decodes the SCCM script and knows the attacker infrastructure', () => {
    const g = newGame('training', shift1)
    run(g, 'source=edr user=SYSTEM | head 1')
    const out = g.blocks[0].items[0]
    expect(out.k).toBe('rows')
    expect(b64dec('RwBlAHQALQBDAGkAbQ')).toBe('Get-Cim')
    expect(tiLookup(newGame('training', shift1), ATT)).toMatch(/MALICIOUS/)
    expect(tiLookup(newGame('training', shift1), PHD.replace('.com', '[.]com'))).toMatch(/MALICIOUS/)
    expect(tiLookup(newGame('training', shift1), '192.0.2.50')).toMatch(/spray/)
    expect(tiLookup(newGame('training', shift1), 'nothing.example')).toMatch(/No data/)
  })
  it('every command costs the shift time it says it does', () => {
    const g = newGame('training', shift1)
    const t0 = g.clock
    run(g, 'ti 198.51.100.77')
    run(g, 'phone priya.singh')
    expect(g.clock - t0).toBe(60 * (1 + 5))
    run(g, 'help')
    expect(g.clock - t0).toBe(60 * 6)
  })
  it('phone calls use the AI only when it is ready, and fall back to fixed answers', () => {
    const g = newGame('training', shift1)
    run(g, 'phone jenna.hart', false)
    expect(g.call).toBeNull()
    expect(JSON.stringify(g.blocks.at(-1))).toMatch(/tapped Approve/)
    const g2 = newGame('training', shift1)
    run(g2, 'phone jenna.hart', true)
    expect(g2.call?.persona).toBe('jenna.hart')
    const r = run(g2, 'did you click a link earlier?', true)
    expect(r.ask?.turns.at(-1)).toEqual({ who: 'analyst', text: 'did you click a link earlier?' })
    run(g2, 'hangup')
    expect(g2.call).toBeNull()
    const g3 = newGame('training', shift1)
    run(g3, 'phone tom.reeves', true)
    expect(g3.call).toBeNull() // no character defined, so a plain voicemail
  })
  it('hints only exist in training mode and cost points', () => {
    const g = newGame('exam', shift1)
    g.sel = 'A2'
    run(g, 'hint')
    expect(g.hints).toBe(0)
    const t = newGame('training', shift1)
    t.sel = 'A2'
    run(t, 'hint')
    expect(t.hints).toBe(1)
    expect(total(t, false)).toBe(-5)
  })
})

describe('clock, business-email-compromise timing and scoring', () => {
  it('new alerts arrive on time and the BEC alert only fires if you did not contain Jenna', () => {
    const g = newGame('training', shift1)
    expect(g.arrived.has('A6')).toBe(false)
    advance(g, 21)
    expect(g.arrived.has('A6')).toBe(true)
    advance(g, 40)
    expect(g.flags.bec).toBe(true)
    expect(g.arrived.has('A7')).toBe(true)
    expect(rowsOf(g, 'source=mail dir=outbound subj=*bank*').total).toBe(1)

    const h = newGame('training', shift1)
    run(h, 'revoke-sessions jenna.hart')
    run(h, 'reset-password jenna.hart')
    advance(h, 60)
    expect(h.flags.bec).toBe(false)
    expect(h.arrived.has('A7')).toBe(false)
    expect(rowsOf(h, 'source=mail dir=outbound subj=*bank*').total).toBe(0)
  })
  it('too-late containment does not prevent it', () => {
    const g = newGame('training', shift1)
    advance(g, 46) // 09:16
    run(g, 'disable-user jenna.hart')
    expect(g.flags.bec).toBe(true)
  })
  it('a perfect investigation scores far more than doing nothing, and wrong containment costs points', () => {
    const none = newGame('exam', shift1)
    advance(none, 200)
    expect(none.over).toBe(true)
    const doNothing = total(none, true)
    expect(doNothing).toBeLessThan(0)

    const good = newGame('exam', shift1)
    good.sel = 'A2'
    run(good, 'source=entra user=jenna.hart | sort time')
    for (const key of ['e_success_foreign', 'e_office_signin']) {
      const e = shift1.build().byKey[key]
      togglePin(good, e.id)
    }
    submitVerdict(good, 'A2', 'incident', 'MFA fatigue')
    const a2 = shift1.alerts.find((a) => a.id === 'A2')!
    expect(gradeAlert(good, a2).pts).toBe(100 + 50)
    expect(gradeAlert(good, a2).miss).toEqual([])

    const bad = newGame('exam', shift1)
    run(bad, 'block-ip 203.0.113.11')
    run(bad, 'isolate FIN-WS-014')
    expect(gradeContain(bad).pts).toBe(-130)
    expect(openAlerts(bad).length).toBe(4)
  })
  it('closing a real incident as benign is penalised hard; closing noise as an incident is milder', () => {
    const g = newGame('exam', shift1)
    submitVerdict(g, 'A2', 'benign', '')
    submitVerdict(g, 'A3', 'incident', '')
    const a2 = shift1.alerts.find((a) => a.id === 'A2')!
    const a3 = shift1.alerts.find((a) => a.id === 'A3')!
    expect(gradeAlert(g, a2).pts).toBe(-150 - 30)
    expect(gradeAlert(g, a3).pts).toBe(-60 - 30)
  })
  it('max score is reachable in principle and shrinks when BEC does not happen', () => {
    const g = newGame('training', shift1)
    const withBec = (() => { advance(g, 60); return maxScore(g) })()
    const h = newGame('training', shift1)
    run(h, 'disable-user jenna.hart')
    advance(h, 60)
    expect(maxScore(h)).toBeLessThan(withBec)
    expect(hm(9, 15)).toBeGreaterThan(0)
  })
})
