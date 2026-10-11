// Shift 5 (Easy): Marlowe Architects, a fictional 70-person architecture firm.
// A leaver copies client drawings on his way out. The skill is judgment: this is
// an HR and legal matter as much as a security one, and three loud alerts are routine.
import { acted, anyActed, defaultNoteTail, did, eachDay, hm, m, makeScenario, memo, mkUsers } from '../common'
import type { Alert, Containment, GameView, ShiftDef, TimelineRow, Wrong } from '../types'

const DOM = 'marlowearch.example'
const OFFICE = '203.0.113.60'
const HOME = 'greg.park.home@mailbox.example'
const CLOUD = 'mega-storage.example'

const FIELDS: Record<string, string> = {
  fileaudit: 'user host op path size',
  proxy: 'user host src method domain url bytes_out cat age action',
  usb: 'host user drive vendor action',
  mail: 'sender rcpt subj att url dir verdict',
  vpn: 'ip user result reason',
}
const SRCDESC: Record<string, string> = { fileaudit: 'File server audit log', proxy: 'Web proxy', usb: 'Removable-drive (device control) log', mail: 'Mail flow / DLP', vpn: 'VPN gateway' }

const USERS = mkUsers([
  ['greg.p', 'ARCH-WS-07', 'Design', 'm01'], ['anita.f', 'FIN-WS-02', 'Finance', 'm02'], ['devon.s', 'ENG-WS-03', 'Engineering', 'm03'], ['joy.n', 'HR-WS-01', 'HR', 'm04'],
  ['claire.m', 'DIR-WS-01', 'Management', 'm05'], ['tariq.b', 'ARCH-WS-02', 'Design', 'm06'], ['lola.e', 'ARCH-WS-04', 'Design', 'm07'], ['sean.w', 'ARCH-WS-05', 'Design', 'm08'],
  ['ruth.g', 'ADMIN-WS-01', 'Admin', 'm09'], ['ollie.k', 'ENG-WS-01', 'Engineering', 'm10'],
], 10, 70)
const U = Object.fromEntries(USERS.map((u) => [u.n, u]))
const SITES: [string, string, number][] = [
  ['www.office.com', 'business', 4000], ['www.archdaily.example', 'design', 8000], ['www.bbc.co.uk', 'news', 9000], ['www.google.com', 'search', 9000],
  ['www.planning-portal.example', 'government', 9000], ['www.linkedin.com', 'social', 8000], ['www.autodesk.example', 'business', 5000],
]
const FOLDERS = ['\\\\FILES\\Projects\\Hartwell', '\\\\FILES\\Projects\\Quay', '\\\\FILES\\Bids\\2026', '\\\\FILES\\Admin\\Templates', '\\\\FILES\\Clients\\Hartwell']

const build = memo(() => makeScenario(20260513, (G) => {
  const { R, pick, ri, ev } = G
  eachDay(USERS, hm(11, 0), (u, base, end) => {
    for (let i = 0; i < ri(18, 30); i++) ev('fileaudit', base + ri(hm(8, 30), end), { user: u.n, host: 'FILES', op: pick(['read', 'read', 'read', 'write']), path: `${pick(FOLDERS)}\\${pick(['plan', 'spec', 'model', 'notes'])}_${ri(100, 999)}.${pick(['dwg', 'pdf', 'docx', 'xlsx'])}`, size: ri(40, 9000) })
    for (let i = 0; i < ri(14, 22); i++) { const s = pick(SITES); ev('proxy', base + ri(hm(8, 30), end), { user: u.n, host: u.host, src: u.ip, method: 'GET', domain: s[0], url: '/' + pick(['', 'home', 'news']), bytes_out: ri(180, 900), cat: s[1], age: s[2], action: 'allowed' }) }
    for (let i = 0; i < ri(3, 6); i++) ev('mail', base + ri(hm(8, 30), end), { sender: pick(['client@hartwell.example', 'planning@council.example', 'orders@suppliers.example']), rcpt: `${u.n}@${DOM}`, subj: pick(['Drawing revision', 'Meeting notes', 'Invoice', 'Site visit Thursday']), att: R() < 0.3 ? 'drawing.pdf' : 'none', url: '-', dir: 'inbound', verdict: 'delivered' })
  })
  ev('vpn', -86400 + hm(9, 5), { ip: '198.51.100.71', user: 'ollie.k', result: 'success', reason: 'mfa satisfied' })
  ev('usb', -86400 + hm(11, 0), { host: 'ARCH-WS-02', user: 'tariq.b', drive: 'E:', vendor: 'Kingston (company-issued)', action: 'mounted' })

  // Greg, yesterday evening
  for (let i = 0; i < 312; i++) ev('fileaudit', -86400 + hm(18, 10) + i * 17, { user: 'greg.p', host: 'FILES', op: 'read', path: `${i % 2 ? '\\\\FILES\\Clients\\Hartwell' : '\\\\FILES\\Bids\\2026'}\\${pick(['plan', 'model', 'bid', 'fees'])}_${ri(100, 999)}.${pick(['dwg', 'pdf', 'xlsx'])}`, size: ri(900, 60000) }, i === 0 ? { key: 'e_files_greg', tag: 'e2raw' } : i < 3 ? { tag: 'e2raw' } : {})
  ev('usb', -86400 + hm(18, 45, 20), { host: 'ARCH-WS-07', user: 'greg.p', drive: 'F:', vendor: 'GENERIC 128GB (personal)', action: 'mounted' }, { key: 'e_usb_greg' })
  ev('proxy', -86400 + hm(19, 20, 10), { user: 'greg.p', host: 'ARCH-WS-07', src: U['greg.p'].ip, method: 'POST', domain: CLOUD, url: '/upload', bytes_out: 1400000000, cat: 'file sharing', age: 900, action: 'allowed' }, { key: 'e_upload_greg', tag: 'e1raw' })
  ev('mail', -86400 + hm(19, 30, 5), { sender: `greg.p@${DOM}`, rcpt: HOME, subj: 'Hartwell models', att: 'hartwell_model_v7.dwg;fees_2026.xlsx', url: '-', dir: 'outbound', verdict: 'delivered' }, { key: 'e_mail_greg', tag: 'e3raw' })
  for (let i = 0; i < 160; i++) ev('fileaudit', hm(10, 0, 10) + i * 2, { user: 'greg.p', host: 'ARCH-WS-07', op: 'delete', path: `C:\\Users\\greg.p\\Documents\\Hartwell\\file_${i}.dwg`, size: ri(900, 60000) }, { cond: 'wipe', tag: i < 3 ? 'e7raw' : undefined, key: i === 0 ? 'e_wipe' : undefined })

  // Decoys
  for (let i = 0; i < 380; i++) ev('fileaudit', hm(2, 0) + i * 6, { user: 'svc-backup', host: 'FILES', op: 'read', path: `${pick(FOLDERS)}\\archive_${i}.bak`, size: ri(900, 90000) }, i === 0 ? { key: 'e_backup', tag: 'e4raw' } : i < 3 ? { tag: 'e4raw' } : {})
  ev('proxy', hm(8, 40, 0), { user: 'anita.f', host: 'FIN-WS-02', src: U['anita.f'].ip, method: 'POST', domain: 'secure-audit-portal.example', url: '/upload/yearend', bytes_out: 480000000, cat: 'business', age: 2200, action: 'allowed' }, { key: 'e_audit_upload', tag: 'e5raw' })
  ev('vpn', hm(2, 14, 33), { ip: '198.51.100.88', user: 'devon.s', result: 'success', reason: 'mfa satisfied' }, { key: 'e_vpn_devon', tag: 'e6raw' })
}))

const ALERTS: Alert[] = [
  { id: 'E1', title: 'Proxy: 1.4 GB upload to personal cloud storage', sev: 'high', src: 'Web proxy', ent: 'greg.p', at: hm(9, 0), sla: m(60), raw: 'e1raw',
    rule: 'More than 1 GB sent in one request to a file-sharing site.',
    kv: [['User', 'greg.p (Senior Architect)'], ['Destination', CLOUD], ['Size', '1.4 GB'], ['When', 'Yesterday 19:20, after hours']],
    best: 'insider', alt: { incident: 50 }, req: ['e_upload_greg', 'e_usb_greg', 'c_hr_greg'],
    why: 'Greg handed in notice two weeks ago and is joining a competitor. After hours he read hundreds of client files, copied them to a personal USB drive, uploaded 1.4 GB to personal cloud storage and emailed drawings to his home address. This is an insider-risk matter for HR and legal, not just security.',
    hints: ['Who is Greg, and is there anything in HR about his employment status?', 'What else did he do that evening? Search fileaudit and usb for greg.p.'] },
  { id: 'E2', title: 'File server: 312 files read in 90 minutes after hours', sev: 'med', src: 'File audit', ent: 'greg.p', at: hm(9, 5), sla: m(90), raw: 'e2raw',
    rule: 'A user read more than 200 files in 2 hours outside 08:00-18:00.',
    kv: [['User', 'greg.p'], ['Folders', 'Clients\\Hartwell, Bids\\2026'], ['Window', 'Yesterday 18:10 - 19:30'], ['Normal for him', 'About 25 reads a day']],
    best: 'insider', alt: { incident: 50 }, req: ['e_files_greg', 'c_hr_greg'],
    why: 'Greg normally reads about 25 files a day and works on a different client. These are the client files and fee bids a competitor would want.',
    hints: ['Compare with his usual daily volume and the folders he normally touches.'] },
  { id: 'E3', title: 'Mail DLP: CAD and fee spreadsheet sent to a personal address', sev: 'med', src: 'Mail flow', ent: 'greg.p', at: hm(9, 10), sla: m(90), raw: 'e3raw',
    rule: 'An attachment of type .dwg or a fee spreadsheet sent to a free-mail domain.',
    kv: [['Sender', 'greg.p'], ['Recipient', HOME], ['Attachments', 'hartwell_model_v7.dwg; fees_2026.xlsx']],
    best: 'insider', alt: { incident: 50 }, req: ['e_mail_greg', 'c_hr_greg'],
    why: 'The same evening, the same person, a personal address. On its own an engineer emailing a drawing home might be sloppy. Together with E1 and E2 it is a pattern.',
    hints: ['Is this the only unusual thing Greg did, or does it match another alert?'] },
  { id: 'E4', title: 'File server: 380 files read by svc-backup', sev: 'med', src: 'File audit', ent: 'svc-backup', at: hm(9, 15), sla: m(120), raw: 'e4raw',
    rule: 'A single account read more than 300 files in 1 hour.',
    kv: [['Account', 'svc-backup'], ['Window', '02:00 - 02:38'], ['Paths', 'All project folders, .bak files']],
    best: 'benign', alt: { fp: 60 }, req: ['e_backup'],
    why: 'The nightly backup service account reads every project folder at 02:00 every night. Compare yesterday at the same time.',
    hints: ['Search fileaudit for svc-backup and compare with yesterday.'] },
  { id: 'E5', title: 'Proxy: 480 MB upload to an external portal', sev: 'med', src: 'Web proxy', ent: 'anita.f', at: hm(9, 20), sla: m(90), raw: 'e5raw',
    rule: 'More than 250 MB sent in one request to an uncommon external site.',
    kv: [['User', 'anita.f (Finance)'], ['Destination', 'secure-audit-portal.example'], ['Category', 'business']],
    best: 'benign', alt: { it: 60 }, req: ['e_audit_upload', 'c_ticket'],
    why: 'Year-end audit pack, approved in ticket TKT-77 and sent to the auditors\' own portal. Large and external does not mean wrong.',
    hints: ['Is there a ticket? Try ask-it or ticket.'] },
  { id: 'E6', title: 'VPN: login at 02:14 from Ireland', sev: 'low', src: 'VPN', ent: 'devon.s', at: hm(9, 25), sla: m(120), raw: 'e6raw',
    rule: 'VPN login outside 06:00-20:00.',
    kv: [['User', 'devon.s (Engineering)'], ['Source', '198.51.100.88 (IE)'], ['MFA', 'satisfied']],
    best: 'benign', alt: { fp: 60 }, req: ['e_vpn_devon', 'c_oncall'],
    why: 'Devon was on call for the structural-monitoring system and travelling in Ireland. The login was MFA-protected and matches the on-call rota.',
    hints: ['Check HR for travel or on-call.'] },
  { id: 'E7', title: 'File audit: 160 files deleted on ARCH-WS-07', sev: 'high', src: 'File audit', ent: 'greg.p', at: hm(10, 5), sla: m(15), raw: 'e7raw', late: 'wipe',
    rule: 'More than 100 files deleted from a user profile in 5 minutes.',
    kv: [['User', 'greg.p'], ['Host', 'ARCH-WS-07'], ['Path', 'Documents\\Hartwell']],
    best: 'insider', alt: { incident: 60 }, req: ['e_wipe', 'e_files_greg'],
    why: 'Greg came in and cleared the local copies. A snapshot of ARCH-WS-07 before 10:00 would have preserved the evidence HR and legal will need.',
    hints: ['This is the evidence being destroyed. The local copy is the proof.'] },
]
const EVD: Record<string, string> = {
  e_upload_greg: 'The 1.4 GB upload to personal cloud storage',
  e_usb_greg: 'Personal 128 GB USB mounted 18:45',
  e_files_greg: '312 client and bid files read after hours',
  e_mail_greg: 'Drawings and fees emailed to a personal address',
  e_backup: 'svc-backup runs the same read every night',
  e_audit_upload: 'The audit-portal upload',
  e_vpn_devon: "Devon's 02:14 VPN login with MFA",
  e_wipe: 'Mass deletion on ARCH-WS-07',
  c_hr_greg: 'Checked HR for Greg\'s employment status',
  c_ticket: 'Found the audit-pack ticket',
  c_oncall: 'Checked Devon\'s on-call or travel',
}
const TI: Record<string, string> = {
  [CLOUD]: 'Reputation: CLEAN but high-risk category · consumer cloud storage · frequent data-exfiltration destination',
  'secure-audit-portal.example': 'Reputation: CLEAN · used by Gantry & Co (Marlowe\'s external auditors)',
  '198.51.100.88': 'Residential broadband · Dublin, IE · no abuse history',
  [OFFICE]: 'Marlowe Architects office egress (internal address)',
}
const PHONE: Record<string, string> = {
  'greg.p': 'Greg P.:\n"I was just tidying up my files before I go. Nothing unusual. Why, is there a problem?"\nHe sounds cautious and does not mention the USB drive or personal email.',
  'joy.n': 'Joy N. (HR):\n"Greg gave notice on the 29th. He leaves on the 16th. I have been told he is going to Orrin Design. Please do not confront him. Legal needs to be involved before anything is said."',
  'anita.f': 'Anita F.:\n"Yes, that is the year-end audit pack. The auditors asked for it by Friday. I raised a ticket."',
  'devon.s': 'Devon S.:\n"I am in Dublin for my sister\'s wedding but I am on call this week. A sensor alarm woke me up and I logged in."',
}
const HR: Record<string, string> = {
  'greg.p': 'Senior Architect · NOTICE GIVEN 04-29 · last day 05-16 · destination: competitor (Orrin Design) · restrictive covenant applies (6 months, clients). Contact HR and legal before any action.',
  'devon.s': 'Structural Engineer · on-call rota this week · approved leave 05-12 to 05-15 (Ireland).',
  'anita.f': 'Finance Manager · year-end audit owner.',
}
const TICKET: Record<string, string> = { 'tkt-77': 'TKT-77 · Approved · requester anita.f\nScope: send the year-end audit pack to the auditors\' secure portal\nSize: about 500 MB · due Friday' }
function askIT(q: string): string {
  if (/audit|anita|secure-audit|year/i.test(q)) return 'IT: Finance is sending the audit pack to the auditors this week, see TKT-77.'
  if (/backup|svc-backup/i.test(q)) return 'IT: svc-backup runs the nightly job at 02:00 across all project folders.'
  if (/vpn|devon|ireland|call/i.test(q)) return 'IT: Devon is on the on-call rota this week.'
  return 'IT: not sure, can you raise a ticket?'
}
const CONTAIN: Containment[] = [
  { label: "Restrict greg.p's USB, download and sharing rights", pts: 40, t: (g) => acted(g, 'restrict-access greg.p') },
  { label: "Take a forensic snapshot of Greg's workstation", pts: 40, t: (g) => acted(g, 'snapshot arch-ws-07') },
  { label: 'Tell HR', pts: 25, t: (g) => acted(g, 'notify hr') },
  { label: 'Tell legal', pts: 25, t: (g) => acted(g, 'notify legal') },
  { label: `Block ${CLOUD}`, pts: 20, t: (g) => acted(g, `block-domain ${CLOUD}`) },
]
const WRONG: Wrong[] = [
  { label: 'Disabled greg.p before HR and legal were involved (tips him off)', pts: -30, t: (g) => acted(g, 'disable-user greg.p') && !acted(g, 'notify hr', 'notify legal') },
  { label: 'Disabled svc-backup (stops all backups)', pts: -50, t: (g) => acted(g, 'disable-user svc-backup') },
  { label: 'Disabled anita.f (approved audit upload)', pts: -40, t: (g) => acted(g, 'disable-user anita.f') },
  { label: 'Blocked the office egress IP (outage)', pts: -80, t: (g) => acted(g, `block-ip ${OFFICE}`) },
]
const CHECKS: Record<string, (g: GameView) => boolean> = {
  c_hr_greg: (g) => did(g, /^(hr|phone)\s+(greg\.p|joy\.n)/i),
  c_ticket: (g) => did(g, /^ticket\s+tkt-77/i) || did(g, /^ask-it\s.*(audit|anita)/i),
  c_oncall: (g) => did(g, /^(hr|phone)\s+devon\.s/i) || did(g, /^ask-it\s.*(vpn|devon|call)/i),
}
function timeline(k: Set<string>, g: GameView): TimelineRow[] {
  const rows: TimelineRow[] = [
    { at: -86400 + hm(18, 10), text: 'Greg reads 312 Hartwell client and bid files after hours', ttp: 'T1005 Data from local system / T1039 network share', found: k.has('e_files_greg') },
    { at: -86400 + hm(18, 45), text: 'He plugs in a personal 128 GB USB drive', ttp: 'T1052.001 Exfiltration over USB', found: k.has('e_usb_greg') },
    { at: -86400 + hm(19, 20), text: 'He uploads 1.4 GB to personal cloud storage', ttp: 'T1567.002 Exfiltration to cloud storage', found: k.has('e_upload_greg') },
    { at: -86400 + hm(19, 30), text: 'He emails a CAD model and the fee spreadsheet to his home address', ttp: 'T1048 Exfiltration over alternative protocol', found: k.has('e_mail_greg') },
  ]
  if (g.flags.wipe) rows.push({ at: hm(10, 0), text: 'The next morning he deletes the local copies from his workstation', ttp: 'T1070.004 File deletion', found: k.has('e_wipe') })
  return rows
}
export const shift5: ShiftDef = {
  id: 'soc-5',
  title: 'Marlowe Architects: the leaver',
  company: 'Marlowe Architects',
  level: 'Easy',
  blurb: 'A senior architect on his notice period copies client files. Insider risk is an HR and legal matter: preserve evidence, do not tip him off.',
  intro: 'You are the analyst covering Marlowe Architects, a fictional 70-person practice, from 09:00 to 11:00. Overnight alerts are waiting. Some are one person, some are routine. Remember that when the person is a colleague, the verdict "insider risk" means HR and legal, not just a block.',
  start: hm(9, 0), end: hm(11, 0), dates: ['05-12', '05-13'],
  fields: FIELDS, srcdesc: SRCDESC, users: USERS, build, alerts: ALERTS, evd: EVD,
  intel: { ti: TI, whois: {}, phone: PHONE, badge: { 'greg.p': 'Badge in 07:58 today · yesterday: in 08:30, out 20:05 (usual hours end 17:30).' }, hr: HR, tickets: TICKET, askIt: askIT, protectedIps: { [OFFICE]: 'this is the office egress address. Everyone loses internet access.' } },
  callable: ['greg.p', 'joy.n', 'anita.f', 'devon.s'],
  triggers: [{
    flag: 'wipe', at: hm(10, 0),
    contained: (g) => anyActed(g, 'snapshot arch-ws-07', 'isolate arch-ws-07'),
    penalty: 80, penaltyLabel: 'Evidence deleted from ARCH-WS-07', okLog: "Greg's workstation preserved before 10:00",
    note: (done, happened) => (!done ? 'The shift ended before 10:00.' : happened ? "Greg deleted his local copies at 10:00 because the workstation had not been preserved." : "You preserved Greg's workstation before he could delete anything."),
  }],
  contain: CONTAIN, wrong: WRONG, checks: CHECKS, timeline,
  gaps: ['USB storage was not restricted for staff who had given notice.', 'Personal cloud storage was not blocked at the proxy.', 'DLP only alerted on email, not on file-server access patterns.', 'No process to raise access monitoring when someone resigns.'],
  noteTail: defaultNoteTail,
  chips: ['help', 'source=fileaudit user=greg.p | stats count by op', 'source=usb', 'hr greg.p', 'source=fileaudit user=svc-backup | stats count by op'],
  cheat: `source=fileaudit user=greg.p | stats count by op
source=usb user=greg.p
source=proxy user=greg.p bytes_out>1000000
hr greg.p     phone joy.n     restrict-access greg.p
snapshot arch-ws-07     notify hr     notify legal     help`,
  solution: {
    cmds: ['snapshot arch-ws-07', 'restrict-access greg.p', 'notify hr', 'notify legal', `block-domain ${CLOUD}`, 'hr greg.p', 'ticket tkt-77', 'hr devon.s'],
    verdicts: [['E1', 'insider'], ['E2', 'insider'], ['E3', 'insider'], ['E4', 'benign'], ['E5', 'benign'], ['E6', 'benign']],
    pins: { E1: ['e_upload_greg', 'e_usb_greg'], E2: ['e_files_greg'], E3: ['e_mail_greg'], E4: ['e_backup'], E5: ['e_audit_upload'], E6: ['e_vpn_devon'] },
  },
}
