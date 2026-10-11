// Shift 1 scenario data: Harlow & Finch Logistics, a fictional company.
// Every name, domain and IP is invented (IPs come from documentation ranges
// 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24). Nothing here touches a
// real system. Adding another shift means adding another file like this one.

export type Src = 'entra' | 'entraaudit' | 'exchange' | 'mail' | 'proxy' | 'edr' | 'vpn' | 'ad'
export type Val = string | number
export interface Ev {
  id: string
  src: Src
  ts: number // seconds from today 00:00 UTC; yesterday is negative
  f: Record<string, Val>
  key?: string
  tag?: string
  cond?: 'bec'
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
  rule: string
  kv: [string, string][]
  best: Verdict
  alt: Partial<Record<Verdict, number>>
  req: string[]
  why: string
  hints: string[]
  late?: 'bec'
}

export const hm = (h: number, m: number, s = 0): number => h * 3600 + m * 60 + s
export const START = hm(8, 30)
export const END = hm(11, 0)
export const DOM = 'harlowfinch.example'
export const OFFICE = '203.0.113.11'
export const ATT = '198.51.100.77'
export const PHD = 'login-micros0ft-secure.com'
export const PHM = 'remit@brightpath-pay.co'
export const SHIFT_ID = 'soc-1'

export const FIELDS: Record<Src, string> = {
  entra: 'user ip geo app dev os result mfa',
  entraaudit: 'user op app publisher scopes ip',
  exchange: 'user op detail ip',
  mail: 'sender rcpt subj att url dir verdict',
  proxy: 'user host src method domain url bytes_out cat age action',
  edr: 'host user proc parent cmd action',
  vpn: 'ip user result reason',
  ad: 'actor op target group dc',
}
export const SRCDESC: Record<Src, string> = {
  entra: 'Entra ID sign-in logs',
  entraaudit: 'Entra ID audit (consents, app changes)',
  exchange: 'Exchange Online mailbox audit',
  mail: 'Mail flow / message trace',
  proxy: 'Web proxy',
  edr: 'Endpoint detection (process events)',
  vpn: 'VPN gateway',
  ad: 'Active Directory domain controller',
}

function mulberry(seed: number): () => number {
  let a = seed | 0
  return () => {
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export interface User { n: string; host: string; dept: string; dev: string; ip: string }
const USER_ROWS: [string, string, string, string][] = [
  ['jenna.hart', 'FIN-WS-019', 'Finance', 'b7f2a0'], ['aisha.khan', 'FIN-WS-021', 'Finance', 'a14c92'],
  ['marcus.o', 'FIN-WS-016', 'Finance', 'e03b71'], ['lena.fischer', 'FIN-WS-011', 'Finance', '5d8e12'],
  ['david.cole', 'FIN-WS-014', 'Finance', '7a90cc'], ['sophie.m', 'FIN-WS-023', 'Finance', '31fe08'],
  ['raj.patel', 'FIN-WS-008', 'Finance', 'c2a6d4'], ['chloe.w', 'FIN-WS-025', 'Finance', '88b1e7'],
  ['ben.arnold', 'FIN-WS-017', 'Finance', '09d5aa'], ['hannah.b', 'FIN-WS-012', 'Finance', 'f46c30'],
  ['tom.reeves', 'WS-SALES-008', 'Sales', '2be9c1'], ['priya.singh', 'WS-SALES-003', 'Sales', 'c55d03'],
  ['olu.adeyemi', 'IT-WS-002', 'IT', 'd70a49'], ['greg.shaw', 'OPS-WS-011', 'Ops', '6c13f5'],
  ['nina.k', 'HR-WS-004', 'HR', '4af2b8'], ['adm.collins', 'INFRA-WS-001', 'IT', '1e77d9'],
]
export const USERS: User[] = USER_ROWS.map((a, i) => ({ n: a[0], host: a[1], dept: a[2], dev: a[3], ip: `10.20.${10 + i}.${20 + i * 3}` }))
export const BY_NAME: Record<string, User> = Object.fromEntries(USERS.map((u) => [u.n, u]))
const FIN = USERS.filter((u) => u.dept === 'Finance')

const APPS = ['Office365 Web', 'Outlook Desktop', 'Teams', 'SharePoint', 'Sage 50', 'Xero']
const SITES: [string, string, number][] = [
  ['www.office.com', 'business', 4200], ['outlook.office365.com', 'business', 4200], ['login.microsoftonline.com', 'business', 4200],
  ['teams.microsoft.com', 'business', 4200], ['contoso-my.sharepoint.com', 'business', 3900], ['www.bbc.co.uk', 'news', 9000],
  ['www.linkedin.com', 'social', 8000], ['github.com', 'tech', 6000], ['stackoverflow.com', 'tech', 6000],
  ['www.dhl.com', 'logistics', 8000], ['www.maersk.com', 'logistics', 8000], ['tracking.dpd.co.uk', 'logistics', 5000],
  ['www.gov.uk', 'government', 9000], ['www.hmrc.gov.uk', 'government', 9000], ['zoom.us', 'business', 5000],
  ['www.google.com', 'search', 9000], ['www.sage.com', 'finance', 7000], ['www.xero.com', 'finance', 6000],
  ['www.theguardian.com', 'news', 9000], ['trade-expo-2026.eu', 'uncategorized', 21], ['docs.google.com', 'business', 6000],
  ['www.royalmail.com', 'logistics', 9000],
]
const SUPP = ['accounts@maersk-logistics.example', 'orders@dpd-freight.example', 'billing@pallet-network.example', 'noreply@sage.example', 'invoices@fuelcard-uk.example', 'team@lloydsfleet.example', 'updates@linkedin.example', 'hr@harlowfinch.example', 'it-notices@harlowfinch.example']
const SUBJ = ['Invoice 20441 attached', 'Your weekly statement', 'Delivery manifest 3318', 'Remittance advice 4468', 'Fuel card statement - March', 'Meeting moved to 14:00', 'Policy reminder: clear desk', 'Team lunch Friday?', 'Re: pallet shortfall - Leeds depot', 'Customs entry confirmation', 'Timesheet reminder', 'Q1 forecast - draft']
export const B64 = 'RwBlAHQALQBDAGkAbQBJAG4AcwB0AGEAbgBjAGUAIABXAGkAbgAzADIAXwBQAHIAbwBkAHUAYwB0ACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIABOAGEAbQBlACwAVgBlAHIAcwBpAG8AbgAgAHwAIABFAHgAcABvAHIAdAAtAEMAcwB2ACAAQwA6AFwAVwBpAG4AZABvAHcAcwBcAEMAQwBNAFwAaQBuAHYALgBjAHMAdgAgAC0ATgBvAFQAeQBwAGUASQBuAGYAbwByAG0AYQB0AGkAbwBuAA=='

export interface Scenario { events: Ev[]; byKey: Record<string, Ev> }
let cached: Scenario | null = null

export function scenario(): Scenario {
  if (cached) return cached
  const R = mulberry(20260317)
  const pick = <T,>(a: T[]): T => a[Math.floor(R() * a.length)]
  const ri = (a: number, b: number): number => a + Math.floor(R() * (b - a + 1))
  const EV: Omit<Ev, 'id'>[] = []
  const ev = (src: Src, ts: number, f: Record<string, Val>, o: { key?: string; tag?: string; cond?: 'bec' } = {}) => {
    EV.push({ src, ts, f, key: o.key, tag: o.tag, cond: o.cond })
  }

  for (const d of [-1, 0]) {
    const base = d * 86400
    const end = d < 0 ? hm(17, 30) : hm(11, 0)
    for (const u of USERS) {
      const wfh = u.n === 'tom.reeves'
      const ipx = wfh ? '82.31.14.9' : OFFICE
      const skipEntra = d === 0 && (u.n === 'jenna.hart' || u.n === 'priya.singh')
      if (!skipEntra) {
        const n = ri(2, 4)
        for (let i = 0; i < n; i++) {
          const t = i === 0 ? ri(hm(7, 30), hm(9, 0)) : ri(hm(9, 15), end)
          const fail = R() < 0.03
          ev('entra', base + t, { user: u.n, ip: ipx, geo: 'Sheffield,GB', app: pick(APPS), dev: u.dev, os: 'Windows 11', result: fail ? 'failure' : 'success', mfa: fail ? 'n/a' : R() < 0.5 ? 'satisfied (token)' : 'push approved' })
        }
      }
      for (let i = 0; i < ri(1, 2); i++) ev('exchange', base + ri(hm(7, 40), end), { user: u.n, op: 'MailboxLogin', detail: 'client=Outlook', ip: ipx })
      const np = ri(28, 40)
      for (let i = 0; i < np; i++) {
        const s = pick(SITES)
        const post = s[0] === 'login.microsoftonline.com' ? R() < 0.5 : R() < 0.06
        ev('proxy', base + ri(hm(8, 0), end), { user: u.n, host: u.host, src: u.ip, method: post ? 'POST' : 'GET', domain: s[0], url: '/' + pick(['', 'home', 'api/v2/items', 'login', 'static/app.js', 'track?id=' + ri(1000, 9999)]), bytes_out: post ? ri(900, 6200) : ri(180, 900), cat: s[1], age: s[2], action: 'allowed' })
      }
      for (let i = 0; i < ri(6, 10); i++) {
        ev('mail', base + ri(hm(7, 30), end), { sender: pick(SUPP), rcpt: `${u.n}@${DOM}`, subj: pick(SUBJ), att: R() < 0.25 ? `invoice_${ri(1000, 9999)}.pdf` : 'none', url: '-', dir: 'inbound', verdict: 'delivered' })
      }
      for (let i = 0; i < ri(1, 3); i++) {
        ev('mail', base + ri(hm(7, 30), end), { sender: `promo${ri(10, 99)}@${pick(['cheapdeals', 'lead-gen', 'win-now'])}.example`, rcpt: `${u.n}@${DOM}`, subj: pick(['You have won!', 'Boost your sales', 'Final notice']), att: 'none', url: '-', dir: 'inbound', verdict: 'quarantined' })
      }
      const procs: [string, string, string][] = [
        ['outlook.exe', 'explorer.exe', '"C:\\Program Files\\Microsoft Office\\Outlook.exe"'],
        ['teams.exe', 'explorer.exe', `"C:\\Users\\${u.n}\\AppData\\Local\\Teams\\teams.exe"`],
        ['chrome.exe', 'explorer.exe', '"C:\\Program Files\\Google\\Chrome\\chrome.exe"'],
        ['excel.exe', 'explorer.exe', '"C:\\Program Files\\Microsoft Office\\EXCEL.EXE" /e'],
        ['notepad.exe', 'explorer.exe', 'notepad.exe'],
        ['AcroRd32.exe', 'outlook.exe', 'AcroRd32.exe invoice.pdf'],
      ]
      for (let i = 0; i < ri(5, 8); i++) {
        const p = pick(procs)
        ev('edr', base + ri(hm(7, 45), end), { host: u.host, user: u.n, proc: p[0], parent: p[1], cmd: p[2], action: 'allowed' })
      }
    }
    ev('ad', base + hm(14, 10), { actor: 'adm.collins', op: 'Member added to Backup Operators', target: 'svc-backup1', group: 'Backup Operators', dc: 'DC01' })
    for (let i = 0; i < 4; i++) ev('ad', base + ri(hm(8, 30), end), { actor: 'olu.adeyemi', op: 'Password reset', target: pick(USERS).n, group: '-', dc: 'DC01' })
  }
  ev('exchange', -86400 + hm(9, 52), { user: 'david.cole', op: 'New-InboxRule', detail: 'name="Newsletters" condition=from contains "@promo" action=MoveToFolder:Newsletters', ip: OFFICE })
  ev('entraaudit', -86400 + hm(11, 5), { user: 'tom.reeves', op: 'Consent to application', app: 'Zoom', publisher: 'Zoom Video Communications (verified)', scopes: 'User.Read,Calendars.Read', ip: '82.31.14.9' })

  // The attack chain
  FIN.forEach((u, i) => {
    ev('mail', hm(7, 41, 12 + i), { sender: PHM, rcpt: `${u.n}@${DOM}`, subj: 'Remittance advice 4471 - Harlow & Finch', att: 'none', url: `https://${PHD}/r/4471`, dir: 'inbound', verdict: 'delivered' }, u.n === 'jenna.hart' ? { key: 'e_mail_deliv' } : {})
  })
  const jh = BY_NAME['jenna.hart']
  ev('proxy', hm(7, 47, 20), { user: 'jenna.hart', host: jh.host, src: jh.ip, method: 'GET', domain: PHD, url: '/r/4471', bytes_out: 310, cat: 'uncategorized', age: 3, action: 'allowed' }, { key: 'e_click' })
  ev('proxy', hm(7, 48, 5), { user: 'jenna.hart', host: jh.host, src: jh.ip, method: 'POST', domain: PHD, url: '/r/4471/login', bytes_out: 412, cat: 'uncategorized', age: 3, action: 'allowed' }, { key: 'e_post', tag: 'a1raw' })
  ev('proxy', hm(7, 55, 41), { user: 'marcus.o', host: 'FIN-WS-016', src: BY_NAME['marcus.o'].ip, method: 'GET', domain: PHD, url: '/r/4471', bytes_out: 310, cat: 'uncategorized', age: 3, action: 'allowed' })
  ev('proxy', hm(8, 2, 9), { user: 'aisha.khan', host: 'FIN-WS-021', src: BY_NAME['aisha.khan'].ip, method: 'GET', domain: PHD, url: '/r/4471', bytes_out: 310, cat: 'uncategorized', age: 3, action: 'allowed' })
  ev('entra', hm(8, 1, 12), { user: 'jenna.hart', ip: OFFICE, geo: 'Sheffield,GB', app: 'Outlook Desktop', dev: 'b7f2a0', os: 'Windows 11', result: 'success', mfa: 'satisfied (token)' }, { key: 'e_office_signin' })
  const prompts: [number, number, number, string][] = [[8, 3, 51, 'no response'], [8, 4, 40, 'no response'], [8, 5, 29, 'denied (user)'], [8, 6, 12, 'no response'], [8, 7, 5, 'no response'], [8, 8, 20, 'no response'], [8, 9, 33, 'no response'], [8, 10, 47, 'no response'], [8, 11, 58, 'no response'], [8, 12, 40, 'no response']]
  const attBase = { user: 'jenna.hart', ip: ATT, geo: 'Bucharest,RO', app: 'Office365 Web', dev: '4c1e9d', os: 'Linux' }
  prompts.forEach((p) => ev('entra', hm(p[0], p[1], p[2]), { ...attBase, result: 'mfa_prompt', mfa: p[3] }, { tag: 'a2raw' }))
  ev('entra', hm(8, 13, 44), { ...attBase, result: 'mfa_prompt', mfa: 'APPROVED' }, { key: 'e_approve', tag: 'a2raw' })
  ev('entra', hm(8, 13, 46), { ...attBase, result: 'success', mfa: 'push approved' }, { key: 'e_success_foreign' })
  ev('exchange', hm(8, 15, 2), { user: 'jenna.hart', op: 'MailboxLogin', detail: 'client=OWA', ip: ATT })
  ev('exchange', hm(8, 19, 31), { user: 'jenna.hart', op: 'New-InboxRule', detail: 'name="." condition=subject contains "invoice","payment","bank","remittance" action=ForwardTo:remit.ops@brightpath-pay.co;MarkAsRead;MoveToFolder:RSS Subscriptions', ip: ATT }, { key: 'e_rule', tag: 'a6raw' })
  ev('entraaudit', hm(8, 22, 40), { user: 'jenna.hart', op: 'Consent to application', app: 'DocSyncPro', publisher: '(unverified)', scopes: 'Mail.ReadWrite,Files.Read.All,offline_access', ip: ATT }, { key: 'e_consent' })
  ev('mail', hm(9, 17, 40), { sender: `jenna.hart@${DOM}`, rcpt: 'ap@brightfreight.example', subj: 'Updated bank details - please action before Friday run', att: 'bank_details_update.pdf', url: '-', dir: 'outbound', verdict: 'delivered' }, { key: 'e_bec', tag: 'a7raw', cond: 'bec' })

  // Decoys
  ev('entra', hm(8, 10, 22), { user: 'priya.singh', ip: '49.36.140.22', geo: 'Mumbai,IN', app: 'Outlook Desktop', dev: 'c55d03', os: 'Windows 11', result: 'success', mfa: 'satisfied (token)' }, { key: 'e_priya_signin', tag: 'a4raw' })
  for (let i = 0; i < 412; i++) {
    const t = hm(8, 5) + Math.floor(i * ((20 * 60) / 412))
    const user = pick(['admin', 'test', 'jenna.hart', 'scan', 'tom.reeves', 'svc-print', 'guest', 'helpdesk', 'raj.patel', 'backup', 'nina.k', 'sales', 'ben.arnold'])
    ev('vpn', t, { ip: `192.0.2.${ri(2, 254)}`, user, result: 'failed', reason: pick(['bad password', 'bad password', 'unknown user']) }, i < 3 ? { tag: 'a3raw' } : {})
  }
  ev('vpn', hm(8, 41), { ip: '82.31.14.9', user: 'tom.reeves', result: 'success', reason: 'mfa satisfied' })
  USERS.forEach((u, i) =>
    ev('edr', hm(8, 34, i * 13), { host: u.host, user: 'SYSTEM', proc: 'powershell.exe', parent: 'ccmexec.exe', cmd: `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -enc ${B64}`, action: 'allowed' }, u.n === 'david.cole' ? { key: 'e_ps', tag: 'a5raw' } : {}),
  )
  ev('ad', hm(9, 31, 10), { actor: 'adm.collins', op: 'Member added to Backup Operators', target: 'svc-backup2', group: 'Backup Operators', dc: 'DC01' })
  ev('ad', hm(9, 44, 52), { actor: 'adm.collins', op: 'Member added to Domain Admins', target: 'svc-backup2', group: 'Domain Admins', dc: 'DC01' }, { key: 'e_da', tag: 'a8raw' })

  EV.sort((a, b) => a.ts - b.ts)
  const events: Ev[] = EV.map((e, i) => ({ ...e, id: `E${1000 + i}` }))
  const byKey: Record<string, Ev> = {}
  for (const e of events) if (e.key) byKey[e.key] = e
  cached = { events, byKey }
  return cached
}

const m = (n: number): number => n * 60

export const ALERTS: Alert[] = [
  { id: 'A1', title: 'Web proxy: POST to newly registered domain', sev: 'low', src: 'Web proxy', ent: 'FIN-WS-019', at: hm(8, 30), sla: m(120), raw: 'a1raw',
    rule: 'Outbound POST to a domain registered less than 14 days ago. Often a SaaS sign-up, an analytics beacon, or a form on a freshly set-up marketing site.',
    kv: [['User', 'jenna.hart'], ['Host', 'FIN-WS-019'], ['Domain age', '3 days'], ['Category', 'uncategorized'], ['Proxy action', 'allowed (monitor mode)']],
    best: 'incident', alt: {}, req: ['e_mail_deliv', 'e_post'],
    why: 'This low-severity alert is the root cause. The POST is a credential submission to a look-alike Microsoft login page, reached from a phishing email delivered to 10 Finance users at 07:41. Everything else in the shift follows from it.',
    hints: ['Where did Jenna get a link to that domain? Mail flow shows what was delivered, and when.', 'Search the proxy for the domain across all users. Who else visited, and did anyone else POST?'] },
  { id: 'A2', title: 'Entra ID: MFA push storm, 11 prompts in 10 minutes', sev: 'med', src: 'Entra ID', ent: 'jenna.hart', at: hm(8, 30), sla: m(60), raw: 'a2raw',
    rule: 'Five or more MFA prompts for one user inside 10 minutes. Often a stuck Outlook mobile app or a mistyped password loop.',
    kv: [['User', 'Jenna Hart, Accounts Payable'], ['Prompt source', `Single IP, ${ATT}`], ['Final result', 'Approved on the 11th prompt'], ['Number matching', 'Not enabled for this tenant']],
    best: 'incident', alt: {}, req: ['e_success_foreign', 'e_office_signin'],
    why: 'Classic MFA fatigue (T1621). The attacker already had the password from the phishing page and spammed pushes until Jenna approved. She was at her desk in Sheffield at 08:01, so a Romanian hosting IP at 08:13 cannot be her.',
    hints: ['Compare where Jenna normally signs in with where the prompts came from. Search entra for her account.', 'Your threat-intel lookup of the source IP may be worth one minute.'] },
  { id: 'A3', title: 'VPN gateway: 412 failed logins from one /24', sev: 'low', src: 'VPN', ent: 'vpn-gw01', at: hm(8, 30), sla: m(120), raw: 'a3raw',
    rule: 'More than 100 failed VPN authentications from a single /24 within 30 minutes.',
    kv: [['Source range', '192.0.2.0/24'], ['Window', '08:05 - 08:27'], ['Targets', '13 account names, some not real'], ['MFA on VPN', 'Enforced']],
    best: 'benign', alt: { fp: 50 }, req: ['c_vpn'],
    why: 'Background internet credential spraying. The question that matters is whether any attempt succeeded, and none did. Blocking the range is a nice extra, not an incident.',
    hints: ['Failures are noise. Did any attempt from that range succeed?'] },
  { id: 'A4', title: 'Entra ID: sign-in from a new country (India)', sev: 'low', src: 'Entra ID', ent: 'priya.singh', at: hm(8, 30), sla: m(120), raw: 'a4raw',
    rule: 'Sign-in from a country not seen for this user in the last 30 days.',
    kv: [['User', 'priya.singh, Sales'], ['Country', 'India (new)'], ['Device', 'Managed'], ['Result', 'Success, MFA satisfied']],
    best: 'benign', alt: { fp: 70 }, req: ['e_priya_signin', 'c_priya'],
    why: 'Expected travel. She is at a booked conference in Mumbai, signing in from her own compliant laptop. Context beats the rule. Disabling her account would have been the wrong move.',
    hints: ['Compare the device ID with her sign-ins yesterday. Then check with HR or ask her directly.'] },
  { id: 'A5', title: 'EDR: encoded PowerShell command', sev: 'high', src: 'EDR', ent: 'FIN-WS-014', at: hm(8, 35), sla: m(30), raw: 'a5raw',
    rule: 'powershell.exe launched with -EncodedCommand. A common technique for hiding payloads.',
    kv: [['Host', 'FIN-WS-014 (david.cole)'], ['Parent', 'ccmexec.exe'], ['Run as', 'SYSTEM'], ['Action', 'allowed']],
    best: 'benign', alt: { it: 60, fp: 50 }, req: ['e_ps', 'c_decode'],
    why: 'ccmexec.exe is the SCCM client and the same command ran on every managed workstation at 08:34. Decoded, it is the daily software-inventory export. Isolating the host would have been the wrong move.',
    hints: ['The command is base64. Decode it.', 'Is this one host, or every workstation? Search edr for the same command line and count by host.'] },
  { id: 'A6', title: 'Exchange: suspicious inbox rule created', sev: 'high', src: 'Exchange audit', ent: 'jenna.hart', at: hm(8, 50), sla: m(30), raw: 'a6raw',
    rule: 'New inbox rule that forwards mail externally or hides messages from the mailbox owner.',
    kv: [['User', 'jenna.hart'], ['Rule', '"." (a single dot)'], ['Forward target', 'external address'], ['Created', '08:19 (alert delayed 31 minutes)']],
    best: 'incident', alt: {}, req: ['e_rule', 'e_success_foreign'],
    why: 'Persistence and mail snooping (T1114.003). A rule named "." that forwards finance mail and hides it is a textbook BEC setup, created from the attacker IP minutes after the MFA approval. Alerts A1, A2 and A6 are one incident.',
    hints: ['Who created the rule and from which IP? Compare with where Jenna was.', 'Attackers rarely stop at one persistence mechanism. What else happened on her account from that IP?'] },
  { id: 'A7', title: 'Mail DLP: outbound email with bank details to external supplier', sev: 'high', src: 'Mail flow', ent: 'jenna.hart', at: hm(9, 20), sla: m(30), raw: 'a7raw', late: 'bec',
    rule: 'Outbound email containing bank account change language sent to an external recipient.',
    kv: [['Sender', 'jenna.hart'], ['Recipient', 'ap@brightfreight.example (a real supplier)'], ['Attachment', 'bank_details_update.pdf']],
    best: 'incident', alt: {}, req: ['e_bec', 'e_rule'],
    why: 'The attacker used the compromised mailbox to ask a real supplier to change bank details. Containing the account before 09:15 would have prevented this. The finance team and the supplier need a call now.',
    hints: ['Did Jenna send this, or did the attacker send it as her? Check the session that sent it.'] },
  { id: 'A8', title: 'AD: new member added to Domain Admins (svc-backup2)', sev: 'high', src: 'Active Directory', ent: 'DC01', at: hm(9, 45), sla: m(60), raw: 'a8raw',
    rule: 'Any addition to Domain Admins outside a change window.',
    kv: [['Actor', 'adm.collins'], ['Account', 'svc-backup2 (service account)'], ['Group', 'Domain Admins'], ['Time', '09:44']],
    best: 'it', alt: { incident: 50, insider: 30 }, req: ['e_da', 'c_ticket'],
    why: 'There is a change ticket (CHG-2240), but it approves Backup Operators on DC01, not Domain Admins. This looks like a mistake, but a service account with domain-admin rights is dangerous either way. The right call is to hand it to IT change management and have the extra group removed.',
    hints: ['Is there a change ticket? Compare what it approves with what actually happened.'] },
]
export const ALERT_BY_ID: Record<string, Alert> = Object.fromEntries(ALERTS.map((a) => [a.id, a]))

export const VERDICTS: [Verdict, string][] = [
  ['incident', 'Escalate: security incident'],
  ['fp', 'Close: false positive (rule was wrong)'],
  ['benign', 'Close: expected activity (rule right, nothing bad)'],
  ['it', 'Hand to IT / Ops'],
  ['insider', 'Escalate: HR + insider risk'],
]
export const VLABEL: Record<string, string> = Object.fromEntries(VERDICTS)

export const EVD: Record<string, string> = {
  e_mail_deliv: 'Phishing email delivered 07:41 (mail trace)',
  e_post: 'Credentials POSTed to look-alike login page (proxy)',
  e_click: 'Link clicked by Jenna 07:47',
  e_office_signin: 'Jenna signed in from the office 08:01 (so 08:13 is not her)',
  e_success_foreign: 'Successful sign-in from Romanian hosting IP 08:13',
  e_approve: 'The MFA approval itself',
  e_rule: 'Hidden forwarding inbox rule 08:19',
  e_consent: 'Malicious OAuth app consent 08:22',
  e_bec: 'Fraudulent bank-details email 09:17',
  e_priya_signin: "Priya's sign-in from her managed laptop",
  e_ps: 'Encoded PowerShell event',
  e_da: 'Domain Admins change 09:44',
  c_vpn: 'Checked whether any VPN attempt succeeded',
  c_priya: 'Verified travel with HR or the user',
  c_decode: 'Decoded the command or counted it across hosts',
  c_ticket: 'Compared the change ticket to the actual change',
}

// Facts the note-feedback AI is given. Trusted, built-in text.
export function noteFacts(a: Alert): string {
  return [
    `Alert: ${a.title} (${a.ent}).`,
    `The correct call was: ${VLABEL[a.best]}.`,
    `What really happened: ${a.why}`,
    `A good handover note covers: ${a.req.map((r) => EVD[r]).join('; ')}.`,
    a.best === 'incident' ? 'It should also say what was contained and what still needs doing (account, mailbox rule, OAuth app, phishing domain and mail, finance team).' : 'It should say why nothing needs escalating.',
  ].join('\n')
}

export const CALLABLE = ['jenna.hart', 'priya.singh', 'aisha.khan', 'marcus.o', 'david.cole', 'adm.collins']
