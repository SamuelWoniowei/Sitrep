// The shift engine: a tiny SIEM-style query language, lookups, containment
// commands, the clock, and scoring. Pure TypeScript with no network, storage
// or DOM access, so it is easy to test.
import {
  ALERTS, ALERT_BY_ID, ATT, BY_NAME, CALLABLE, END, FIELDS, PHD, SRCDESC, START, VLABEL, hm, scenario,
  type Alert, type Ev, type Src, type Verdict,
} from './data'

export type Mode = 'training' | 'exam'
export interface ChatTurn { who: 'analyst' | 'persona'; text: string }
export type Item =
  | { k: 'msg'; t: string; cls?: 'ok' | 'bad' | 'warn' }
  | { k: 'res'; t: string }
  | { k: 'rows'; vis: Ev[]; mode: 'raw' | 'table' | 'grid'; cols: string[]; grid?: { head: string[]; rows: (string | number)[][] } }
export interface Block { cmd: string; cost: number; items: Item[]; meta?: string; skip?: boolean }
export interface Game {
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
  becDecided: boolean
  bec: boolean
  hints: number
  hintUse: Record<string, number>
  over: boolean
  blocks: Block[]
  call: { persona: string; turns: ChatTurn[] } | null
  toasts: string[]
}
export interface ExecResult { ask?: { persona: string; turns: ChatTurn[]; slot: Item & { k: 'res' } } }

const sc = () => scenario()

export function newGame(mode: Mode): Game {
  const g: Game = {
    mode, clock: START, sel: null, decided: {}, pins: {}, actions: new Set(), log: [], hist: [], cmdHist: [],
    arrived: new Set(), becDecided: false, bec: false, hints: 0, hintUse: {}, over: false, blocks: [], call: null, toasts: [],
  }
  for (const a of ALERTS) if (!a.late && a.at <= START) g.arrived.add(a.id)
  log(g, 'Shift started')
  return g
}
export function log(g: Game, m: string): void { g.log.unshift({ t: g.clock, m }) }
export function visible(g: Game, e: Ev): boolean { return e.ts <= g.clock && (!e.cond || (e.cond === 'bec' && g.bec)) }
export function evById(id: string): Ev | undefined { return sc().events.find((e) => e.id === id) }

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
  let rows = sc().events.filter((e) => visible(g, e) && tests.every((t) => t(e)))
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

const TI: Record<string, string> = {
  [ATT]: 'AS64500 HostBulk LLC · Bucharest, RO · commercial hosting / VPS range\n23 abuse reports in the last 7 days (phishing, credential stuffing)\nNot a corporate network. Not a known consumer VPN provider.\nReputation: MALICIOUS',
  [PHD]: 'Reputation: MALICIOUS · 31 of 90 engines flag it\nTyposquat of a Microsoft sign-in page (the "o" in "micros0ft" is a zero)\nMatches a credential-harvest kit fingerprint · first seen 03-14',
  'brightpath-pay.co': 'Reputation: SUSPICIOUS · registered 4 days ago\nSending infrastructure for 6 other phishing campaigns this week\nOften used as a forwarding / drop address for stolen mail',
  '203.0.113.11': 'Harlow & Finch corporate egress (internal address)',
  '49.36.140.22': 'Consumer mobile ISP · Mumbai, IN · no abuse history',
  '82.31.14.9': 'Residential broadband · Sheffield, GB · no abuse history',
  'trade-expo-2026.eu': 'Reputation: CLEAN · small events site, registered 21 days ago, 3 visits from H&F',
}
export function tiLookup(x: string): string {
  const k = x.toLowerCase().replace(/\[\.\]/g, '.')
  if (TI[k]) return TI[k]
  if (/^192\.0\.2\./.test(k)) return 'Range seen in ~1,900 abuse reports per day · generic internet scanner / credential-spray botnet · no targeted activity against H&F'
  if (/^[a-f0-9]{32,64}$/.test(k)) return 'Hash not seen before · no detections'
  return 'No data. Not seen in any feed.'
}
const WHOIS: Record<string, string> = {
  [PHD]: "Domain:      login-micros0ft-secure.com\nCreated:     03-14 (3 days ago)\nRegistrar:   privacy-protected\nNameserver:  cloudflare\nTLS cert:    Let's Encrypt, issued 03-14",
  'brightpath-pay.co': 'Domain:      brightpath-pay.co\nCreated:     03-13 (4 days ago)\nRegistrar:   privacy-protected\nMX:          yes (receives mail)',
  'trade-expo-2026.eu': 'Domain:      trade-expo-2026.eu\nCreated:     02-24 (21 days ago)\nRegistrant:  Expo Events Ltd (visible)\nMX:          yes',
  'brightfreight.example': 'Domain:      brightfreight.example\nCreated:     2011\nRegistrant:  Bright Freight Ltd (existing H&F supplier)',
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
// Fixed phone answers. When the local AI is available these are replaced by a
// live conversation, but they stay the fallback so the shift always works.
export const PHONE: Record<string, string> = {
  'jenna.hart': 'Jenna Hart (desk 2214):\n"My phone kept buzzing around eight. I thought the app was glitching, so I tapped Approve to make it stop. Did I do something wrong?"\nShe did not start a sign-in from Romania. She was at her desk. She also remembers clicking a remittance link earlier and typing her password into "the Microsoft page".',
  'priya.singh': 'Priya Singh:\n"Yes that was me. I landed in Mumbai this morning for the partner conference and I am on my work laptop."',
  'aisha.khan': 'Aisha Khan:\n"I clicked the remittance link but the page looked off, so I closed it. I did not type anything."',
  'marcus.o': 'Marcus O.:\n"Opened it, thought the address looked odd, closed it. Nothing typed."',
  'david.cole': 'David Cole:\n"I am not running anything special. My machine did slow down for a minute around half eight."',
  'adm.collins': 'Adam Collins (infra):\n"Oh no. I picked Domain Admins from the dropdown instead of Backup Operators. Can you get it reverted?"',
}
const BADGE: Record<string, string> = { 'jenna.hart': 'Main entrance IN 07:32 · no OUT recorded · swipe at finance floor 07:34. Physically in the building.', 'priya.singh': 'No badge activity for 3 days (travelling).' }
const HR: Record<string, string> = {
  'jenna.hart': 'Accounts Payable · full-time · no leave booked · line manager: finance director.',
  'priya.singh': 'Sales Executive · APPROVED business travel Sheffield to Mumbai 03-16 to 03-21 (partner conference) · company laptop issued.',
  'adm.collins': 'Infrastructure admin · joined 2019 · no concerns on file.',
}
const TICKET: Record<string, string> = { 'chg-2240': 'CHG-2240 · Approved · requester adm.collins\nScope: add svc-backup2 to BACKUP OPERATORS on DC01\nWindow: 09:30 - 10:30 today\nNotes: needed for new backup agent. No domain-level privileges requested.' }
function askIT(q: string): string {
  if (/sccm|inventory|powershell|encod|8:3|ccm/i.test(q)) return 'Platform team: SCCM software inventory runs daily at 08:30 on every managed workstation. The encoded script is the standard CCM inventory export.'
  if (/vpn|spray|192\.0\.2|brute/i.test(q)) return 'Network team: that range hits the VPN every few days. MFA is enforced and nothing has got through historically.'
  if (/jenna|rule|forward|consent|docsync/i.test(q)) return 'Helpdesk: no ticket from Jenna today. DocSyncPro is not on our approved app list.'
  return 'IT: not sure, can you raise a ticket?'
}

export const COSTS: Record<string, number> = {
  ti: 1, whois: 1, b64: 0, phone: 5, badge: 3, hr: 3, 'ask-it': 3, ticket: 2, 'revoke-sessions': 2, 'reset-password': 2, 'disable-user': 2,
  'delete-rule': 2, 'revoke-consent': 2, 'block-domain': 2, 'block-ip': 2, 'purge-mail': 3, isolate: 2, 'remove-group': 2, 'notify-finance': 3,
  hint: 0, help: 0, fields: 0, alerts: 0, clear: 0, hangup: 0,
}
export const HELP = `SEARCH     source=entra user=jenna.hart result=success
           key=value · key!=value · wildcards (*) · bytes_out>400 · bare words match anywhere
           earliest=08:00 latest=08:30   (today only)
PIPES      | sort -time | head 20 | tail 5 | table time,user,ip | dedup ip
           | stats count by ip | top domain
SOURCES    ${Object.keys(FIELDS).join(' · ')}
           fields <source>  lists the field names
LOOKUPS    ti <ip|domain|hash>   whois <domain>   b64 <string>
           phone <user>   badge <user>   hr <user>   ask-it <question>   ticket <id>
ACTIONS    revoke-sessions <user> · reset-password <user> · disable-user <user>
           delete-rule <user> · revoke-consent <user> <app>
           block-domain <domain> · block-ip <ip|cidr> · purge-mail <subject text>
           isolate <host> · remove-group <account> <group> · notify-finance
OTHER      alerts · hint (training only) · hangup (end a phone call) · clear
Every search or lookup costs shift time. Click any log line to pin it as evidence for the selected alert.`

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

function runCmd(g: Game, b: Block, c: string, rest: string, w: string[], aiReady: boolean): ExecResult {
  const arg = w[1] || ''
  switch (c) {
    case 'help': res(b, HELP); break
    case 'clear': break
    case 'hangup': msg(b, 'You are not on a call.', 'warn'); break
    case 'alerts': {
      const open = ALERTS.filter((a) => g.arrived.has(a.id) && !g.decided[a.id])
      res(b, open.length ? open.map((a) => `${a.id}  ${a.title}  [${a.ent}]`).join('\n') : 'No open alerts.')
      break
    }
    case 'fields': {
      const s = arg.toLowerCase() as Src
      if (FIELDS[s]) res(b, `${s} (${SRCDESC[s]})\n${FIELDS[s].split(' ').join(', ')}\nPlus the implicit fields: source, id`)
      else res(b, (Object.keys(FIELDS) as Src[]).map((k) => `${k.padEnd(11)}${SRCDESC[k]}\n${' '.repeat(11)}${FIELDS[k]}`).join('\n'))
      break
    }
    case 'ti': if (!arg) { msg(b, 'Usage: ti <ip|domain|hash>', 'bad'); b.cost = 0 } else res(b, tiLookup(arg)); break
    case 'whois': if (!arg) { msg(b, 'Usage: whois <domain>', 'bad'); b.cost = 0 } else res(b, WHOIS[arg.toLowerCase().replace(/\[\.\]/g, '.')] || `No record found for ${arg}.`); break
    case 'b64': {
      if (!rest) { msg(b, 'Usage: b64 <base64 string>', 'bad'); break }
      const d = b64dec(rest.replace(/^-enc\w*\s+/i, ''))
      res(b, d === null ? 'Not valid base64.' : `Decoded (UTF-16LE):\n${d}`)
      break
    }
    case 'phone': {
      const u = arg.toLowerCase()
      if (!BY_NAME[u]) { res(b, `Unknown user "${arg}".`); break }
      if (u === 'adm.collins' && g.clock < hm(9, 45)) { res(b, 'Adam Collins is in a meeting, no answer.'); break }
      if (aiReady && CALLABLE.includes(u)) {
        g.call = { persona: u, turns: [] }
        msg(b, `Calling ${u}… connected. Type what you want to ask, in your own words. Each question costs a minute. Type "hangup" to end the call.`, 'ok')
        msg(b, 'This person is played by your local AI. They only know what they would really know.', undefined)
        break
      }
      res(b, PHONE[u] || `${u}: straight to voicemail.`)
      break
    }
    case 'badge': { const u = arg.toLowerCase(); res(b, BADGE[u] || (BY_NAME[u] ? `${u}: normal swipe pattern, nothing unusual.` : 'Unknown user.')); break }
    case 'hr': { const u = arg.toLowerCase(); res(b, HR[u] || (BY_NAME[u] ? `${BY_NAME[u].dept} · no flags on file.` : 'Unknown user.')); break }
    case 'ask-it': res(b, askIT(rest)); break
    case 'ticket': res(b, TICKET[arg.toLowerCase()] || `Ticket ${arg} not found.`); break
    case 'hint': {
      if (g.mode !== 'training') { msg(b, 'Hints are disabled in exam mode.', 'warn'); break }
      if (!g.sel) { msg(b, 'Select an alert first.', 'warn'); break }
      const h = ALERT_BY_ID[g.sel].hints
      const used = g.hintUse[g.sel] ?? 0
      g.hintUse[g.sel] = used + 1
      g.hints++
      res(b, `HINT (${g.sel}): ${h[Math.min(used, h.length - 1)]}\n(-5 points)`)
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
  if (c === 'revoke-sessions' || c === 'reset-password' || c === 'disable-user') {
    if (!BY_NAME[a]) return bad(`Unknown user "${w[1] ?? ''}".`)
    const t = { 'revoke-sessions': `All refresh tokens and sessions revoked for ${a}.`, 'reset-password': `Password reset for ${a}. User must set a new one at next sign-in.`, 'disable-user': `Account ${a} disabled.` }[c]
    ok(t, `${c} ${a}`)
  } else if (c === 'delete-rule') {
    if (!BY_NAME[a]) return bad('Unknown user.')
    const has = sc().events.some((e) => e.src === 'exchange' && e.f.user === a && e.key === 'e_rule' && visible(g, e))
    ok(has ? `Removed 1 suspicious inbox rule ("." forwarding to external address) from ${a}.` : `No suspicious rules found for ${a}. Nothing removed.`, `${c} ${a}`)
  } else if (c === 'revoke-consent') {
    const app = w.slice(2).join(' ').toLowerCase()
    if (!BY_NAME[a] || !app) return bad('Usage: revoke-consent <user> <app>')
    ok(`Consent for app "${w.slice(2).join(' ')}" revoked for ${a}.`, `${c} ${a} ${app}`)
  } else if (c === 'block-domain') {
    const d = (w[1] || '').toLowerCase().replace(/\[\.\]/g, '.')
    if (!d) return bad('Usage: block-domain <domain>')
    ok(`Domain ${d} blocked at the proxy and mail gateway.`, `${c} ${d}`)
  } else if (c === 'block-ip') {
    const d = (w[1] || '').toLowerCase()
    if (!d) return bad('Usage: block-ip <ip|cidr>')
    ok(d === '203.0.113.11' ? `Blocked ${d} at the perimeter. WARNING: this is the corporate egress address. Staff report they cannot reach Microsoft 365.` : `Blocked ${d} at the firewall.`, `${c} ${d}`)
  } else if (c === 'purge-mail') {
    const t = rest.toLowerCase()
    if (!t) return bad('Usage: purge-mail <subject text>')
    const n = sc().events.filter((e) => e.src === 'mail' && visible(g, e) && e.f.dir === 'inbound' && String(e.f.subj).toLowerCase().includes(t) && e.f.verdict === 'delivered').length
    ok(`Searched all mailboxes for subject containing "${rest}". Soft-deleted ${n} message${n === 1 ? '' : 's'}.`, `purge-mail ${t}`)
  } else if (c === 'isolate') {
    const h = (w[1] || '').toLowerCase()
    if (!h) return bad('Usage: isolate <host>')
    ok(`Host ${w[1]} network-isolated by EDR.`, `isolate ${h}`)
  } else if (c === 'remove-group') {
    const g2 = w.slice(2).join(' ').toLowerCase()
    if (!a || !g2) return bad('Usage: remove-group <account> <group>')
    ok(`Removed ${w[1]} from ${w.slice(2).join(' ')}.`, `remove-group ${a} ${g2}`)
  } else if (c === 'notify-finance') {
    ok('Finance director and AP team notified: do not act on any "updated bank details" emails; verify supplier changes by phone.', 'notify-finance')
  }
}

/* ---------------- clock ---------------- */

export function advance(g: Game, mins: number): void {
  for (let i = 0; i < mins && !g.over; i++) {
    g.clock += 60
    if (!g.becDecided && g.clock >= hm(9, 15)) {
      g.becDecided = true
      const A = g.actions
      const contained = (A.has('revoke-sessions jenna.hart') && A.has('reset-password jenna.hart')) || A.has('disable-user jenna.hart')
      g.bec = !contained
      if (contained) log(g, "Jenna's account contained before 09:15")
    }
    for (const a of ALERTS) {
      if (g.arrived.has(a.id)) continue
      if (a.late === 'bec' && !g.bec) continue
      if (a.at <= g.clock) { g.arrived.add(a.id); log(g, `New alert ${a.id}: ${a.title}`); g.toasts.push(`New alert: ${a.title}`) }
    }
    if (g.clock >= END) { endShift(g); break }
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
  for (const p of Object.values(g.pins)) for (const id of p) { const e = evById(id); if (e?.key) s.add(e.key) }
  return s
}
const CHK: Record<string, (g: Game) => boolean> = {
  c_vpn: (g) => g.hist.some((h) => /source=vpn/i.test(h) && (/result=(success|\*|"?s)/i.test(h) || (/stats|top/i.test(h) && /result/i.test(h)))),
  c_priya: (g) => g.hist.some((h) => /^(hr|phone)\s+priya\.singh/i.test(h)),
  c_decode: (g) => g.hist.some((h) => /^b64\s+/i.test(h) || (/source=edr/i.test(h) && /-enc|powershell/i.test(h) && /stats|top|dedup/i.test(h))),
  c_ticket: (g) => g.hist.some((h) => /^ticket\s+chg-2240/i.test(h)),
}
export function reqMet(g: Game, r: string): boolean { return r.startsWith('c_') ? !!CHK[r]?.(g) : pinnedKeys(g).has(r) }

export function submitVerdict(g: Game, alertId: string, v: Verdict, note: string): void {
  if (g.decided[alertId]) return
  g.decided[alertId] = { v, t: g.clock, note }
  log(g, `${alertId} decided: ${VLABEL[v]}`)
  if (g.mode === 'training') {
    const a = ALERT_BY_ID[alertId]
    const p = gradeAlert(g, a).pts
    g.toasts.push(`${alertId}: ${v === a.best ? 'correct' : 'not the best call'} (${p >= 0 ? '+' : ''}${p})`)
  }
}

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

interface Containment { label: string; pts: number; t: (A: Set<string>) => boolean }
export const CONTAIN: Containment[] = [
  { label: "Revoke Jenna's sessions", pts: 40, t: (A) => A.has('revoke-sessions jenna.hart') },
  { label: "Reset Jenna's password", pts: 40, t: (A) => A.has('reset-password jenna.hart') },
  { label: 'Delete the hidden inbox rule', pts: 40, t: (A) => A.has('delete-rule jenna.hart') },
  { label: 'Revoke the DocSyncPro consent', pts: 40, t: (A) => A.has('revoke-consent jenna.hart docsyncpro') },
  { label: `Block ${PHD}`, pts: 30, t: (A) => A.has(`block-domain ${PHD}`) },
  { label: 'Block brightpath-pay.co', pts: 30, t: (A) => A.has('block-domain brightpath-pay.co') },
  { label: 'Purge the phishing email from all mailboxes', pts: 40, t: (A) => A.has('purge-mail remittance advice 4471') },
  { label: `Block ${ATT}`, pts: 20, t: (A) => A.has(`block-ip ${ATT}`) },
  { label: 'Remove svc-backup2 from Domain Admins', pts: 40, t: (A) => A.has('remove-group svc-backup2 domain admins') },
  { label: 'Block the 192.0.2.0/24 spray range', pts: 15, t: (A) => A.has('block-ip 192.0.2.0/24') },
]
export const WRONG: { label: string; pts: number; t: (A: Set<string>) => boolean }[] = [
  { label: 'Isolated FIN-WS-014 (running legitimate SCCM)', pts: -50, t: (A) => A.has('isolate fin-ws-014') },
  { label: 'Disabled priya.singh (legitimate traveller)', pts: -50, t: (A) => A.has('disable-user priya.singh') },
  { label: 'Blocked the corporate egress IP 203.0.113.11 (outage)', pts: -80, t: (A) => A.has('block-ip 203.0.113.11') },
  { label: 'Disabled adm.collins on a hunch', pts: -40, t: (A) => A.has('disable-user adm.collins') },
  { label: 'Isolated a host with no evidence against it', pts: -30, t: (A) => [...A].some((x) => x.startsWith('isolate ') && !['isolate fin-ws-019', 'isolate fin-ws-014'].includes(x)) },
]
export interface ContainGrade { items: { label: string; pts: number; done: boolean }[]; bad: { label: string; pts: number }[]; pts: number }
export function gradeContain(g: Game): ContainGrade {
  const items = CONTAIN.map((c) => ({ label: c.label, pts: c.pts, done: c.t(g.actions) }))
  const bad = WRONG.filter((w) => w.t(g.actions))
  let pts = items.filter((i) => i.done).reduce((s, i) => s + i.pts, 0) + bad.reduce((s, w) => s + w.pts, 0)
  if (g.bec) {
    const done = g.actions.has('notify-finance')
    if (done) pts += 30
    items.push({ label: 'Notify Finance about the fraudulent bank-details email', pts: 30, done })
  }
  return { items, bad, pts }
}
export function total(g: Game, final: boolean): number {
  let t = 0
  for (const a of ALERTS) { const gr = gradeAlert(g, a); if (g.decided[a.id] || final) t += gr.pts }
  t += gradeContain(g).pts - 5 * g.hints
  if (g.bec) t -= 100
  return t
}
export function maxScore(g: Game): number {
  let m = 0
  for (const a of ALERTS) { if (a.late === 'bec' && !g.bec) continue; m += 100 + 25 * a.req.length }
  return m + CONTAIN.reduce((s, c) => s + c.pts, 0)
}
export function openAlerts(g: Game): Alert[] { return ALERTS.filter((a) => g.arrived.has(a.id) && !g.decided[a.id]) }

export interface TimelineRow { at: number; text: string; ttp: string; found: boolean }
export function timeline(g: Game): TimelineRow[] {
  const k = pinnedKeys(g)
  const rows: TimelineRow[] = [
    { at: hm(7, 41), text: 'Phishing email "Remittance advice 4471" delivered to 10 Finance users', ttp: 'T1566.002 Spearphishing link', found: k.has('e_mail_deliv') },
    { at: hm(7, 48), text: 'Jenna types her password into a fake Microsoft sign-in page', ttp: 'T1056.003 / T1078 Valid accounts', found: k.has('e_post') },
    { at: hm(8, 3), text: 'Attacker logs in with the stolen password and sends 11 MFA pushes', ttp: 'T1621 MFA request generation', found: k.has('e_office_signin') || k.has('e_success_foreign') },
    { at: hm(8, 13), text: 'Jenna approves a push. Attacker is in from a Romanian hosting IP', ttp: 'T1078.004 Cloud accounts', found: k.has('e_success_foreign') },
    { at: hm(8, 19), text: 'Hidden inbox rule forwards finance mail to an external address', ttp: 'T1114.003 Email forwarding rule', found: k.has('e_rule') },
    { at: hm(8, 22), text: 'Malicious OAuth app "DocSyncPro" granted persistent mail and file access', ttp: 'T1528 Steal application access token', found: k.has('e_consent') || g.actions.has('revoke-consent jenna.hart docsyncpro') },
  ]
  if (g.bec) rows.push({ at: hm(9, 17), text: 'Fraudulent "updated bank details" email sent to a real supplier', ttp: 'T1657 Financial theft (BEC)', found: k.has('e_bec') })
  return rows
}
