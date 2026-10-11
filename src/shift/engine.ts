// The shift engine: a tiny SIEM-style query language, lookups, containment
// commands, the clock, and scoring. It is generic: everything scenario-specific
// comes from the active ShiftDef (see types.ts). Pure TypeScript with no
// network, storage or DOM access, so it is easy to test.
import type { Alert, Ev, Sev, ShiftDef, Verdict, TimelineRow, Scenario } from './types'
import { hm } from './common'

export type Mode = 'training' | 'exam'
export interface ChatTurn { who: 'analyst' | 'persona'; text: string }
export type Item =
  | { k: 'msg'; t: string; cls?: 'ok' | 'bad' | 'warn' }
  | { k: 'res'; t: string }
  | { k: 'rows'; vis: Ev[]; mode: 'raw' | 'table' | 'grid'; cols: string[]; grid?: { head: string[]; rows: (string | number)[][] } }
// Ticket workflow: every alert is a ticket you must claim before you work it,
// acknowledged within a window set by its severity. Escalations need a
// written handover (what, who, when, actions) that is scored.
export interface Escalation { summary: string; who: string; when: string; actions: string }
export interface Ticket {
  num: string
  owner: string | null
  claimedAt?: number
  sev?: Sev // the severity you assessed
  esc?: Escalation
  notes: { t: number; text: string }[]
  trail: { t: number; m: string }[]
}
export type TicketStatus = 'New' | 'In progress' | 'Escalated' | 'Transferred' | 'Closed'
export const ACK_MIN: Record<Sev, number> = { high: 10, med: 20, low: 45 }
export const WIP_MAX = 3
export const ESC_FIELDS: [keyof Escalation, string, string][] = [
  ['summary', 'What happened', 'One or two sentences: what the alert was and what you concluded.'],
  ['who', 'Who and what is affected', 'Users, hosts, accounts, data or money involved.'],
  ['when', 'When', 'First and last malicious activity, in UTC, and when you found it.'],
  ['actions', 'Done and needed next', 'What you contained already, and what the receiving team must do.'],
]
export interface Block { cmd: string; cost: number; items: Item[]; meta?: string; skip?: boolean }
export interface Game {
  def: ShiftDef
  mode: Mode
  clock: number
  sel: string | null
  decided: Record<string, { v: Verdict; t: number; note: string }>
  pins: Record<string, string[]>
  actions: Set<string>
  log: { t: number; m: string }[]
  hist: string[]
  cmdHist: string[]
  arrived: Set<string>
  flags: Record<string, boolean> // set by triggers when the bad thing happened
  flagDone: Record<string, boolean> // trigger already checked
  hints: number
  hintUse: Record<string, number>
  over: boolean
  blocks: Block[]
  call: { persona: string; turns: ChatTurn[] } | null
  toasts: string[]
  tickets: Record<string, Ticket>
}
export interface ExecResult { ask?: { persona: string; turns: ChatTurn[]; slot: Item & { k: 'res' } } }

export const scn = (g: Game): Scenario => g.def.build()
export const alertById = (g: Game, id: string): Alert | undefined => g.def.alerts.find((a) => a.id === id)

export function newGame(mode: Mode, def: ShiftDef): Game {
  const g: Game = {
    def, mode, clock: def.start, sel: null, decided: {}, pins: {}, actions: new Set(), log: [], hist: [], cmdHist: [],
    arrived: new Set(), flags: {}, flagDone: {}, hints: 0, hintUse: {}, over: false, blocks: [], call: null, toasts: [], tickets: {},
  }
  for (const a of def.alerts) if (!a.late && a.at <= def.start) arrive(g, a)
  log(g, 'Shift started')
  return g
}
export function log(g: Game, m: string): void { g.log.unshift({ t: g.clock, m }) }
function arrive(g: Game, a: Alert): void {
  g.arrived.add(a.id)
  const i = g.def.alerts.findIndex((x) => x.id === a.id)
  g.tickets[a.id] = { num: `TKT-${4001 + i * 7}`, owner: null, notes: [], trail: [{ t: Math.max(a.at, g.def.start), m: 'Ticket created from alert, unassigned' }] }
}
export const trueSev = (a: Alert): Sev => a.tsev ?? (a.best === 'incident' || a.best === 'insider' ? 'high' : a.best === 'it' ? 'med' : 'low')
export function ticketStatus(g: Game, id: string): TicketStatus {
  const d = g.decided[id]
  if (d) return d.v === 'incident' || d.v === 'insider' ? 'Escalated' : d.v === 'it' ? 'Transferred' : 'Closed'
  return g.tickets[id]?.owner ? 'In progress' : 'New'
}
export const inProgress = (g: Game): Alert[] => g.def.alerts.filter((a) => g.arrived.has(a.id) && !g.decided[a.id] && g.tickets[a.id]?.owner)
export function claimTicket(g: Game, id: string): { ok: boolean; msg: string } {
  const a = alertById(g, id)
  const t = g.tickets[id]
  if (!a || !t || !g.arrived.has(id)) return { ok: false, msg: `No ticket for "${id}". Type "alerts" to list the queue.` }
  if (g.decided[id]) return { ok: false, msg: `${t.num} is already ${ticketStatus(g, id).toLowerCase()}.` }
  if (t.owner) return { ok: false, msg: `${t.num} is already yours.` }
  if (inProgress(g).length >= WIP_MAX) return { ok: false, msg: `You already have ${WIP_MAX} tickets in progress. Close, escalate or transfer one before claiming another.` }
  t.owner = 'you'
  t.claimedAt = g.clock
  t.trail.push({ t: g.clock, m: 'Claimed by you' })
  log(g, `Claimed ${t.num} (${a.id})`)
  return { ok: true, msg: `${t.num} claimed. ${a.title}. Acknowledge target was ${ACK_MIN[a.sev]} min from arrival.` }
}
export function addNote(g: Game, id: string | null, text: string): { ok: boolean; msg: string } {
  const t = id ? g.tickets[id] : undefined
  if (!id || !t) return { ok: false, msg: 'Select a ticket first.' }
  if (!t.owner) return { ok: false, msg: `Claim ${t.num} before adding work notes.` }
  if (!text.trim()) return { ok: false, msg: 'Usage: note <text>' }
  t.notes.push({ t: g.clock, text: text.trim().slice(0, 500) })
  return { ok: true, msg: `Work note added to ${t.num}.` }
}
export function visible(g: Game, e: Ev): boolean { return e.ts <= g.clock && (!e.cond || !!g.flags[e.cond]) }
export function evById(g: Game, id: string): Ev | undefined { return scn(g).events.find((e) => e.id === id) }

/* ---------------- query language ---------------- */

function wild(p: string): RegExp {
  return new RegExp('^' + p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i')
}
function splitPipes(s: string): string[] {
  const out: string[] = []
  let cur = ''
  let q = false
  for (const c of s) {
    if (c === '"') q = !q
    if (c === '|' && !q) { out.push(cur); cur = '' } else cur += c
  }
  out.push(cur)
  return out.map((x) => x.trim())
}
export function toks(s: string): string[] {
  const r: string[] = []
  const re = /([\w.]+(?:!=|>=|<=|=|>|<)"[^"]*")|("[^"]*")|(\S+)/g
  let m: RegExpExecArray | null
  while ((m = re.exec(s))) r.push(m[0])
  return r
}
const unq = (v: string): string => v.replace(/^"|"$/g, '')
function todSecs(v: string): number | null {
  const m = v.match(/^(\d{1,2}):(\d{2})$/)
  return m ? hm(+m[1], +m[2]) : null
}
export const tod = (ts: number): number => ((ts % 86400) + 86400) % 86400
type Test = (e: Ev) => boolean
function compile(term: string): Test {
  const m = term.match(/^([\w.]+)(!=|>=|<=|=|>|<)(.*)$/)
  if (!m) {
    const w = unq(term).toLowerCase()
    return (e) => `${e.src} ${Object.values(e.f).join(' ')}`.toLowerCase().includes(w)
  }
  const [, k, op, v0] = m
  const v = unq(v0)
  const kl = k.toLowerCase()
  if (kl === 'source') { const re = wild(v); return (e) => re.test(e.src) }
  if (kl === 'earliest' || kl === 'latest') {
    const s = todSecs(v)
    if (s === null) return () => false
    return (e) => (e.ts < 0 ? false : kl === 'earliest' ? tod(e.ts) >= s : tod(e.ts) <= s)
  }
  if (kl === 'id') { const re = wild(v); return (e) => re.test(e.id) }
  if (op === '=' || op === '!=') {
    const re = wild(v)
    return (e) => {
      const val = e.f[kl]
      const hit = val !== undefined && re.test(String(val))
      return op === '=' ? hit : !hit
    }
  }
  const n = parseFloat(v)
  return (e) => {
    const val = parseFloat(String(e.f[kl]))
    if (Number.isNaN(val)) return false
    return op === '>' ? val > n : op === '<' ? val < n : op === '>=' ? val >= n : val <= n
  }
}
export interface QueryResult { err?: string; rows: Ev[]; total: number; mode: 'raw' | 'table' | 'grid'; cols: string[]; grid?: { head: string[]; rows: (string | number)[][] } }
export function runQuery(g: Game, line: string): QueryResult {
  const parts = splitPipes(line)
  const tests = toks(parts[0]).map(compile)
  let rows = scn(g).events.filter((e) => visible(g, e) && tests.every((t) => t(e)))
  const total = rows.length
  let mode: 'raw' | 'table' | 'grid' = 'raw'
  let cols: string[] = []
  let grid: QueryResult['grid']
  const val = (e: Ev, f: string): string | number => (f === 'source' ? e.src : f === 'time' ? e.ts : e.f[f] ?? '-')
  for (const p of parts.slice(1)) {
    const a = toks(p)
    const c = (a[0] || '').toLowerCase()
    const arg = a.slice(1)
    if (c === 'head') rows = rows.slice(0, parseInt(arg[0]) || 10)
    else if (c === 'tail') rows = rows.slice(-(parseInt(arg[0]) || 10))
    else if (c === 'sort') {
      let f = arg[0] || 'time'
      let d = 1
      if (f.startsWith('-')) { d = -1; f = f.slice(1) }
      rows = [...rows].sort((x, y) => {
        const xv = val(x, f), yv = val(y, f)
        const n = parseFloat(String(xv)) - parseFloat(String(yv))
        return d * (Number.isNaN(n) ? String(xv).localeCompare(String(yv)) : n)
      })
    } else if (c === 'dedup') {
      const f = arg[0]
      const seen = new Set<string | number>()
      rows = rows.filter((e) => { const v = val(e, f); if (seen.has(v)) return false; seen.add(v); return true })
    } else if (c === 'table') { mode = 'table'; cols = arg.join('').split(',').filter(Boolean) }
    else if (c === 'stats') {
      const by = arg.findIndex((x) => x.toLowerCase() === 'by')
      const f = by >= 0 ? arg[by + 1] : null
      if (!f) grid = { head: ['count'], rows: [[rows.length]] }
      else {
        const cnt: Record<string, number> = {}
        rows.forEach((e) => { const v = String(val(e, f)); cnt[v] = (cnt[v] || 0) + 1 })
        grid = { head: [f, 'count'], rows: Object.entries(cnt).sort((x, y) => y[1] - x[1]) }
      }
      mode = 'grid'
    } else if (c === 'top') {
      const f = arg[0] || 'source'
      const cnt: Record<string, number> = {}
      rows.forEach((e) => { const v = String(val(e, f)); cnt[v] = (cnt[v] || 0) + 1 })
      grid = { head: [f, 'count'], rows: Object.entries(cnt).sort((x, y) => y[1] - x[1]).slice(0, 10) }
      mode = 'grid'
    } else return { err: `Unknown pipe command "${a[0] ?? ''}". Try: head, tail, sort, dedup, table, stats count by <field>, top <field>.`, rows: [], total: 0, mode, cols }
  }
  return { rows, total, mode, cols, grid }
}

/* ---------------- lookups ---------------- */

export function tiLookup(g: Game, x: string): string {
  const k = x.toLowerCase().replace(/\[\.\]/g, '.')
  const it = g.def.intel
  if (it.ti[k]) return it.ti[k]
  for (const [re, txt] of it.tiRules ?? []) if (re.test(k)) return txt
  if (/^[a-f0-9]{32,64}$/.test(k)) return 'Hash not seen before · no detections'
  return 'No data. Not seen in any feed.'
}
export function b64dec(s: string): string | null {
  try {
    const bin = atob(s.replace(/\s/g, ''))
    let out = ''
    for (let i = 0; i < bin.length; i += 2) out += String.fromCharCode(bin.charCodeAt(i) | ((bin.charCodeAt(i + 1) || 0) << 8))
    return out
  } catch {
    return null
  }
}

export const COSTS: Record<string, number> = {
  ti: 1, whois: 1, b64: 0, phone: 5, badge: 3, hr: 3, 'ask-it': 3, ticket: 2, 'revoke-sessions': 2, 'reset-password': 2, 'disable-user': 2,
  'delete-rule': 2, 'revoke-consent': 2, 'block-domain': 2, 'block-ip': 2, 'purge-mail': 3, isolate: 2, 'remove-group': 2, 'notify-finance': 3,
  notify: 3, snapshot: 3, 'restrict-access': 2, 'disable-key': 2, 'delete-account': 2, terminate: 2, lock: 2, 'delete-file': 2, 'rotate-secret': 3,
  hint: 0, help: 0, fields: 0, alerts: 0, tickets: 0, claim: 1, note: 0, helpdesk: 2, clear: 0, hangup: 0,
}
export function helpText(def: ShiftDef): string {
  return `SEARCH     source=entra user=jenna.hart result=success
           key=value · key!=value · wildcards (*) · bytes_out>400 · bare words match anywhere
           earliest=08:00 latest=08:30   (today only)
PIPES      | sort -time | head 20 | tail 5 | table time,user,ip | dedup ip
           | stats count by ip | top domain
SOURCES    ${Object.keys(def.fields).join(' · ')}
           fields <source>  lists the field names
TICKETS    alerts (or tickets)   claim <alert id>   note <text>
           Claim a ticket before you work it (max ${WIP_MAX} at once). Work notes go on the selected ticket.
LOOKUPS    ti <ip|domain|hash>   whois <domain>   b64 <string>
           phone <user>   badge <user>   hr <user>   ask-it <question>
           ticket <id>  (look up an IT helpdesk ticket; also "helpdesk <id>")
ACTIONS    revoke-sessions <user> · reset-password <user> · disable-user <user>
           restrict-access <user> · delete-rule <user> · revoke-consent <user> <app>
           block-domain <domain> · block-ip <ip|cidr> · purge-mail <subject text>
           isolate <host> · snapshot <host> · delete-file <host> <path>
           remove-group <account> <group> · delete-account <name>
           disable-key <id> · rotate-secret <name> · terminate <resource> · lock <resource>
           notify <finance|hr|legal|dpo|ir-lead|vendor|management>
OTHER      alerts · hint (training only) · hangup (end a phone call) · clear
Every search or lookup costs shift time. Click any log line to pin it as evidence for the selected alert.`
}

/* ---------------- running a command ---------------- */

export function exec(g: Game, rawLine: string, aiReady: boolean): ExecResult {
  const line = rawLine.trim()
  if (!line || g.over) return {}
  let out: ExecResult = {}

  if (g.call) {
    if (/^hangup$/i.test(line)) {
      const b = mkBlock('hangup', 0)
      b.items.push({ k: 'msg', t: 'Call ended.' })
      g.call = null
      g.blocks.push(b)
      return {}
    }
    const b = mkBlock(`you › ${line}`, 1)
    g.call.turns.push({ who: 'analyst', text: line.slice(0, 300) })
    const slot: Item & { k: 'res' } = { k: 'res', t: '…' }
    b.items.push(slot)
    g.blocks.push(b)
    advance(g, 1)
    return { ask: { persona: g.call.persona, turns: [...g.call.turns], slot } }
  }

  g.hist.push(line)
  g.cmdHist.push(line)
  const w = line.split(/\s+/)
  const c = w[0].toLowerCase()
  const rest = line.slice(w[0].length).trim()
  const known = c in COSTS
  const b = mkBlock(line, known ? COSTS[c] : 1)
  g.blocks.push(b)
  if (known) out = runCmd(g, b, c, rest, w, aiReady)
  else {
    const r = runQuery(g, line)
    if (r.err) { b.items.push({ k: 'msg', t: r.err, cls: 'bad' }); b.cost = 0 }
    else {
      const vis = r.rows.slice(0, 200)
      b.items.push({ k: 'rows', vis, mode: r.mode, cols: r.cols, grid: r.grid })
      b.meta = `${r.total} events matched${r.rows.length !== r.total ? ` · ${r.rows.length} after pipes` : ''}${r.rows.length > 200 ? ' · showing first 200' : ''}`
      if (r.total === 0) b.items.push({ k: 'msg', t: 'No events matched. Check field names with "fields <source>" or loosen the search.', cls: 'warn' })
    }
  }
  if (c === 'clear') { g.blocks = [] }
  else if (b.cost) advance(g, Math.ceil(b.cost))
  return out
}
function mkBlock(cmd: string, cost: number): Block { return { cmd, cost, items: [] } }
const msg = (b: Block, t: string, cls?: 'ok' | 'bad' | 'warn') => b.items.push({ k: 'msg', t, cls })
const res = (b: Block, t: string) => b.items.push({ k: 'res', t })
const userOf = (g: Game, n: string) => g.def.users.find((u) => u.n === n.toLowerCase())

function runCmd(g: Game, b: Block, c: string, rest: string, w: string[], aiReady: boolean): ExecResult {
  const arg = w[1] || ''
  const it = g.def.intel
  switch (c) {
    case 'help': res(b, helpText(g.def)); break
    case 'clear': break
    case 'hangup': msg(b, 'You are not on a call.', 'warn'); break
    case 'alerts':
    case 'tickets': {
      const open = g.def.alerts.filter((a) => g.arrived.has(a.id) && !g.decided[a.id])
      res(b, open.length ? open.map((a) => `${g.tickets[a.id]?.num}  ${a.id}  ${ticketStatus(g, a.id).padEnd(11)} ${a.sev.toUpperCase().padEnd(6)} ${a.title}  [${a.ent}]`).join('\n') : 'No open tickets.')
      break
    }
    case 'claim': {
      const q = (arg || g.sel || '').trim().toLowerCase()
      const al = g.def.alerts.find((x) => x.id.toLowerCase() === q || g.tickets[x.id]?.num.toLowerCase() === q)
      const r = claimTicket(g, al?.id ?? q)
      if (r.ok && al) { g.sel = al.id; msg(b, r.msg, 'ok') } else { msg(b, r.msg, 'bad'); b.cost = 0 }
      break
    }
    case 'note': {
      const r = addNote(g, g.sel, rest)
      msg(b, r.msg, r.ok ? 'ok' : 'bad')
      break
    }
    case 'fields': {
      const s = arg.toLowerCase()
      if (g.def.fields[s]) res(b, `${s} (${g.def.srcdesc[s]})\n${g.def.fields[s].split(' ').join(', ')}\nPlus the implicit fields: source, id`)
      else res(b, Object.keys(g.def.fields).map((k) => `${k.padEnd(11)}${g.def.srcdesc[k]}\n${' '.repeat(11)}${g.def.fields[k]}`).join('\n'))
      break
    }
    case 'ti': if (!arg) { msg(b, 'Usage: ti <ip|domain|hash>', 'bad'); b.cost = 0 } else res(b, tiLookup(g, arg)); break
    case 'whois': if (!arg) { msg(b, 'Usage: whois <domain>', 'bad'); b.cost = 0 } else res(b, it.whois[arg.toLowerCase().replace(/\[\.\]/g, '.')] || `No record found for ${arg}.`); break
    case 'b64': {
      if (!rest) { msg(b, 'Usage: b64 <base64 string>', 'bad'); break }
      const d = b64dec(rest.replace(/^-enc\w*\s+/i, ''))
      res(b, d === null ? 'Not valid base64.' : `Decoded (UTF-16LE):\n${d}`)
      break
    }
    case 'phone': {
      const u = arg.toLowerCase()
      if (!userOf(g, u) && !(u in it.phone)) { res(b, `Unknown user "${arg}".`); break }
      const busy = it.phoneBusy?.(u, g.clock)
      if (busy) { res(b, busy); break }
      if (aiReady && g.def.callable.includes(u)) {
        g.call = { persona: u, turns: [] }
        msg(b, `Calling ${u}… connected. Type what you want to ask, in your own words. Each question costs a minute. Type "hangup" to end the call.`, 'ok')
        msg(b, 'This person is played by your local AI. They only know what they would really know.', undefined)
        break
      }
      res(b, it.phone[u] || `${u}: straight to voicemail.`)
      break
    }
    case 'badge': { const u = arg.toLowerCase(); res(b, it.badge[u] || (userOf(g, u) ? `${u}: normal swipe pattern, nothing unusual.` : 'Unknown user.')); break }
    case 'hr': { const u = arg.toLowerCase(); res(b, it.hr[u] || (userOf(g, u) ? `${userOf(g, u)!.dept} · no flags on file.` : 'Unknown user.')); break }
    case 'ask-it': res(b, it.askIt(rest)); break
    case 'helpdesk':
    case 'ticket': res(b, it.tickets[arg.toLowerCase()] || `Ticket ${arg} not found.`); break
    case 'hint': {
      if (g.mode !== 'training') { msg(b, 'Hints are disabled in exam mode.', 'warn'); break }
      if (!g.sel) { msg(b, 'Select an alert first.', 'warn'); break }
      const h = alertById(g, g.sel)?.hints ?? []
      const used = g.hintUse[g.sel] ?? 0
      g.hintUse[g.sel] = used + 1
      g.hints++
      res(b, `HINT (${g.sel}): ${h[Math.min(used, h.length - 1)] ?? 'No hint for this one.'}\n(-5 points)`)
      break
    }
    default: action(g, b, c, rest, w)
  }
  return {}
}

function action(g: Game, b: Block, c: string, rest: string, w: string[]): void {
  const a = (w[1] || '').toLowerCase()
  const ok = (t: string, key: string) => { g.actions.add(key); log(g, `Action: ${key}`); msg(b, t, 'ok') }
  const bad = (t: string) => { msg(b, t, 'bad'); b.cost = 0 }
  const tail = (n: number) => w.slice(n).join(' ')
  if (c === 'revoke-sessions' || c === 'reset-password' || c === 'disable-user') {
    if (!userOf(g, a) && !g.def.intel.phone[a] && !/^(krbtgt|svc[._-]|msol_|adm\.)/.test(a)) return bad(`Unknown user "${w[1] ?? ''}".`)
    const t = { 'revoke-sessions': `All refresh tokens and sessions revoked for ${a}.`, 'reset-password': `Password reset for ${a}. User must set a new one at next sign-in.`, 'disable-user': `Account ${a} disabled.` }[c]
    ok(t as string, `${c} ${a}`)
  } else if (c === 'restrict-access') {
    if (!a) return bad('Usage: restrict-access <user>')
    ok(`Download, USB and external-sharing rights removed for ${a}. The account still works and nothing is deleted.`, `${c} ${a}`)
  } else if (c === 'delete-rule') {
    if (!a) return bad('Unknown user.')
    const has = scn(g).events.some((e) => e.src === 'exchange' && e.f.user === a && e.key === 'e_rule' && visible(g, e))
    ok(has ? `Removed 1 suspicious inbox rule ("." forwarding to external address) from ${a}.` : `No suspicious rules found for ${a}. Nothing removed.`, `${c} ${a}`)
  } else if (c === 'revoke-consent') {
    const app = tail(2).toLowerCase()
    if (!a || !app) return bad('Usage: revoke-consent <user> <app>')
    ok(`Consent for app "${tail(2)}" revoked for ${a}.`, `${c} ${a} ${app}`)
  } else if (c === 'block-domain') {
    const d = (w[1] || '').toLowerCase().replace(/\[\.\]/g, '.')
    if (!d) return bad('Usage: block-domain <domain>')
    ok(`Domain ${d} blocked at the proxy and mail gateway.`, `${c} ${d}`)
  } else if (c === 'block-ip') {
    const d = (w[1] || '').toLowerCase()
    if (!d) return bad('Usage: block-ip <ip|cidr>')
    const warn = g.def.intel.protectedIps?.[d]
    ok(warn ? `Blocked ${d} at the perimeter. WARNING: ${warn}` : `Blocked ${d} at the firewall.`, `${c} ${d}`)
  } else if (c === 'purge-mail') {
    const t = rest.toLowerCase()
    if (!t) return bad('Usage: purge-mail <subject text>')
    const n = scn(g).events.filter((e) => e.src === 'mail' && visible(g, e) && e.f.dir === 'inbound' && String(e.f.subj).toLowerCase().includes(t) && e.f.verdict === 'delivered').length
    ok(`Searched all mailboxes for subject containing "${rest}". Soft-deleted ${n} message${n === 1 ? '' : 's'}.`, `purge-mail ${t}`)
  } else if (c === 'isolate') {
    if (!a) return bad('Usage: isolate <host>')
    ok(`Host ${w[1]} network-isolated by EDR.`, `isolate ${a}`)
  } else if (c === 'snapshot') {
    if (!a) return bad('Usage: snapshot <host>')
    ok(`Forensic snapshot (disk and memory) of ${w[1]} taken and stored read-only.`, `snapshot ${a}`)
  } else if (c === 'delete-file') {
    if (!a || !w[2]) return bad('Usage: delete-file <host> <path>')
    ok(`Deleted ${w[2]} on ${w[1]}.`, `delete-file ${a} ${tail(2).toLowerCase()}`)
  } else if (c === 'remove-group') {
    const g2 = tail(2).toLowerCase()
    if (!a || !g2) return bad('Usage: remove-group <account> <group>')
    ok(`Removed ${w[1]} from ${tail(2)}.`, `remove-group ${a} ${g2}`)
  } else if (c === 'delete-account') {
    if (!a) return bad('Usage: delete-account <name>')
    ok(`Account ${w[1]} deleted, with its keys and sessions.`, `delete-account ${a}`)
  } else if (c === 'disable-key') {
    if (!a) return bad('Usage: disable-key <access key id>')
    ok(`Access key ${w[1]} deactivated.`, `disable-key ${a}`)
  } else if (c === 'rotate-secret') {
    if (!a) return bad('Usage: rotate-secret <name>')
    ok(`Secret "${tail(1)}" rotated. Dependent services will pick up the new value.`, `rotate-secret ${tail(1).toLowerCase()}`)
  } else if (c === 'terminate') {
    if (!a) return bad('Usage: terminate <resource or fleet tag>')
    ok(`Resources matching "${tail(1)}" terminated.`, `terminate ${tail(1).toLowerCase()}`)
  } else if (c === 'lock') {
    if (!a) return bad('Usage: lock <resource>')
    ok(`${w[1]} locked: new access is denied until it is reviewed.`, `lock ${a}`)
  } else if (c === 'notify') {
    if (!a) return bad('Usage: notify <finance|hr|legal|dpo|ir-lead|vendor|management>')
    ok(`${w[1]} has been told and will follow up.`, `notify ${a}`)
  } else if (c === 'notify-finance') {
    ok('Finance director and AP team notified: do not act on any "updated bank details" emails; verify supplier changes by phone.', 'notify-finance')
  }
}

/* ---------------- clock ---------------- */

export function advance(g: Game, mins: number): void {
  for (let i = 0; i < mins && !g.over; i++) {
    g.clock += 60
    for (const t of g.def.triggers) {
      if (g.flagDone[t.flag] || g.clock < t.at) continue
      g.flagDone[t.flag] = true
      const contained = t.contained(g)
      g.flags[t.flag] = !contained
      if (contained) log(g, t.okLog)
    }
    for (const a of g.def.alerts) {
      if (g.arrived.has(a.id)) continue
      if (a.late && !g.flags[a.late]) continue
      if (a.at <= g.clock) { arrive(g, a); log(g, `New alert ${a.id}: ${a.title}`); g.toasts.push(`New alert: ${a.title}`) }
    }
    if (g.clock >= g.def.end) { endShift(g); break }
  }
}
export function endShift(g: Game): void { g.over = true; g.call = null }

/* ---------------- evidence, decisions, scoring ---------------- */

export function togglePin(g: Game, id: string): boolean {
  if (!g.sel) return false
  const p = g.pins[g.sel] ?? (g.pins[g.sel] = [])
  const i = p.indexOf(id)
  if (i >= 0) p.splice(i, 1); else p.push(id)
  return true
}
export function isPinned(g: Game, id: string): boolean { return Object.values(g.pins).some((p) => p.includes(id)) }
export function pinnedKeys(g: Game): Set<string> {
  const s = new Set<string>()
  for (const p of Object.values(g.pins)) for (const id of p) { const e = evById(g, id); if (e?.key) s.add(e.key) }
  return s
}
export function reqMet(g: Game, r: string): boolean { return r.startsWith('c_') ? !!g.def.checks[r]?.(g) : pinnedKeys(g).has(r) }

export function submitVerdict(g: Game, alertId: string, v: Verdict, note: string, opts?: { sev?: Sev; esc?: Escalation }): void {
  if (g.decided[alertId]) return
  const esc = v === 'incident' || v === 'insider'
  const tk = g.tickets[alertId]
  if (tk) {
    if (!tk.owner) tk.owner = 'you'
    if (opts?.sev) tk.sev = opts.sev
    if (esc && opts?.esc) { tk.esc = opts.esc; note = ESC_FIELDS.map(([k, l]) => `${l}: ${opts.esc![k]}`).join('\n') }
    tk.trail.push({ t: g.clock, m: `${esc ? 'Escalated' : v === 'it' ? 'Transferred to IT / Ops' : 'Closed'}: ${VLABEL[v]}` })
  }
  g.decided[alertId] = { v, t: g.clock, note }
  log(g, `${alertId} decided: ${VLABEL[v]}`)
  if (g.mode === 'training') {
    const a = alertById(g, alertId)
    if (!a) return
    const p = gradeAlert(g, a).pts
    g.toasts.push(`${alertId}: ${v === a.best ? 'correct' : 'not the best call'} (${p >= 0 ? '+' : ''}${p})`)
  }
}

export const VERDICTS: [Verdict, string][] = [
  ['incident', 'Escalate to IR: true positive, security incident'],
  ['fp', 'Close: false positive (rule was wrong)'],
  ['benign', 'Close: true positive but expected activity'],
  ['it', 'Transfer to IT / Ops'],
  ['insider', 'Escalate to HR + insider risk'],
]
export const VLABEL: Record<string, string> = Object.fromEntries(VERDICTS)

export interface AlertGrade { pts: number; notes: string[]; found: string[]; miss: string[] }
export function gradeAlert(g: Game, a: Alert): AlertGrade {
  const d = g.decided[a.id]
  const out: AlertGrade = { pts: 0, notes: [], found: [], miss: [] }
  for (const r of a.req) (reqMet(g, r) ? out.found : out.miss).push(r)
  if (!d) {
    if (g.arrived.has(a.id)) { out.pts = a.best === 'incident' ? -150 : -40; out.notes.push('Never decided') }
    return out
  }
  if (d.v === a.best) out.pts += 100
  else if (a.alt[d.v] !== undefined) out.pts += a.alt[d.v] as number
  else out.pts -= a.best === 'incident' ? 150 : 60
  out.pts += out.found.length * 25
  if (!out.found.length) out.pts -= 30
  if (d.t > a.at + a.sla) { out.pts -= 30; out.notes.push('Missed SLA') }
  return out
}

// Ticket-handling points, kept apart from the verdict grade: acknowledging in
// time, assessing severity, and (for a true escalation) a complete handover.
const RANK: Record<Sev, number> = { low: 0, med: 1, high: 2 }
const goodField = (v: string | undefined): boolean => !!v && v.trim().length >= 20 && v.trim().split(/\s+/).length >= 4
export function gradeTicket(g: Game, a: Alert): { pts: number; notes: string[]; escOk: number } {
  const t = g.tickets[a.id]
  const out = { pts: 0, notes: [] as string[], escOk: 0 }
  if (!t) return out
  if (t.claimedAt !== undefined && t.claimedAt > a.at + ACK_MIN[a.sev] * 60) { out.pts -= 10; out.notes.push(`Slow to acknowledge (target ${ACK_MIN[a.sev]} min)`) }
  const d = g.decided[a.id]
  if (!d) return out
  if (t.sev) {
    const diff = Math.abs(RANK[t.sev] - RANK[trueSev(a)])
    if (diff === 0) out.pts += 10
    else if (diff === 2) { out.pts -= 10; out.notes.push(`Severity ${t.sev} vs real ${trueSev(a)}`) }
  }
  const escalated = d.v === 'incident' || d.v === 'insider'
  if (escalated && (a.best === 'incident' || a.best === 'insider')) {
    if (!t.esc) { out.pts -= 20; out.notes.push('Escalated with no handover summary') }
    else { out.escOk = ESC_FIELDS.filter(([k]) => goodField(t.esc![k])).length; out.pts += 5 * out.escOk }
  }
  return out
}
export interface ContainGrade { items: { label: string; pts: number; done: boolean }[]; bad: { label: string; pts: number }[]; pts: number }
export function gradeContain(g: Game): ContainGrade {
  const items = g.def.contain.filter((c) => !c.when || c.when(g)).map((c) => ({ label: c.label, pts: c.pts, done: c.t(g) }))
  const bad = g.def.wrong.filter((w) => w.t(g))
  const pts = items.filter((i) => i.done).reduce((s, i) => s + i.pts, 0) + bad.reduce((s, w) => s + w.pts, 0)
  return { items, bad, pts }
}
export function total(g: Game, final: boolean): number {
  let t = 0
  for (const a of g.def.alerts) { const gr = gradeAlert(g, a); if (g.decided[a.id] || final) t += gr.pts; if (g.decided[a.id] || g.tickets[a.id]?.owner) t += gradeTicket(g, a).pts }
  t += gradeContain(g).pts - 5 * g.hints
  for (const tr of g.def.triggers) if (g.flags[tr.flag]) t -= tr.penalty
  return t
}
export function maxScore(g: Game): number {
  let m = 0
  for (const a of g.def.alerts) { if (a.late && !g.flags[a.late]) continue; m += 100 + 25 * a.req.length + 10 + (a.best === 'incident' || a.best === 'insider' ? 20 : 0) }
  return m + g.def.contain.filter((c) => !c.when || c.when(g)).reduce((s, c) => s + c.pts, 0)
}
export function openAlerts(g: Game): Alert[] { return g.def.alerts.filter((a) => g.arrived.has(a.id) && !g.decided[a.id]) }
export function noteFacts(g: Game, a: Alert): string {
  return [
    `Alert: ${a.title} (${a.ent}).`,
    `The correct call was: ${VLABEL[a.best]}.`,
    `What really happened: ${a.why}`,
    `A good handover note covers: ${a.req.map((r) => g.def.evd[r]).join('; ')}.`,
    g.def.noteTail(a),
  ].join('\n')
}
export function timeline(g: Game): TimelineRow[] { return g.def.timeline(pinnedKeys(g), g) }
