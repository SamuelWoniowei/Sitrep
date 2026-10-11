// Shift 3 (Starter): Tidewater Books, a fictional five-shop bookseller.
// A found USB stick, commodity malware, and three alerts that only look alarming.
import { acted, anyActed, defaultNoteTail, did, eachDay, hm, m, makeScenario, memo, mkUsers } from '../common'
import type { Alert, Containment, GameView, ShiftDef, TimelineRow, Wrong } from '../types'

const SHOP = '203.0.113.30'
const SPRAY = '192.0.2.88'
const C2 = 'cdn-update-svc.net'

const FIELDS: Record<string, string> = {
  edr: 'host user proc parent cmd action sig',
  usb: 'host user drive vendor action',
  proxy: 'user host src method domain url bytes_out cat age action',
  entra: 'user ip geo app dev result mfa',
}
const SRCDESC: Record<string, string> = { edr: 'Endpoint detection and antivirus', usb: 'Removable-drive (device control) log', proxy: 'Web proxy', entra: 'Entra ID sign-in logs' }

const USERS = mkUsers([
  ['dan.w', 'SHOP3-PC2', 'Retail', '5a5a01'], ['kim.p', 'SHOP3-PC1', 'Retail', '5a5a02'], ['sue.m', 'MKT-PC1', 'Marketing', '5a5a03'],
  ['olu.a', 'IT-LAP-01', 'IT', '5a5a04'], ['pat.h', 'SHOP1-PC1', 'Retail', '5a5a05'], ['ivy.c', 'SHOP2-PC1', 'Retail', '5a5a06'],
  ['raf.b', 'WH-PC1', 'Warehouse', '5a5a07'], ['liz.t', 'FIN-PC1', 'Finance', '5a5a08'], ['joe.n', 'SHOP4-PC1', 'Retail', '5a5a09'],
  ['mia.d', 'SHOP5-PC1', 'Retail', '5a5a10'], ['ned.f', 'MKT-PC2', 'Marketing', '5a5a11'], ['bea.s', 'HQ-PC1', 'Management', '5a5a12'],
], 10, 60)
const U = Object.fromEntries(USERS.map((u) => [u.n, u]))
const SITES: [string, string, number][] = [
  ['www.office.com', 'business', 4000], ['www.bookdb.example', 'business', 3000], ['www.bbc.co.uk', 'news', 9000], ['www.google.com', 'search', 9000],
  ['www.royalmail.com', 'logistics', 9000], ['www.gov.uk', 'government', 9000], ['www.publisher-portal.example', 'business', 2500], ['www.youtube.com', 'media', 9000],
]

const build = memo(() => makeScenario(20260412, (G) => {
  const { pick, ri, ev } = G
  eachDay(USERS, hm(9, 30), (u, base, end, d) => {
    if (!(d === 0 && u.n === 'olu.a')) for (let i = 0; i < ri(1, 2); i++) ev('entra', base + ri(hm(7, 30), end), { user: u.n, ip: SHOP, geo: 'Bristol,GB', app: pick(['Office365 Web', 'Outlook Desktop']), dev: u.dev, result: 'success', mfa: 'satisfied (token)' })
    for (let i = 0; i < ri(18, 28); i++) {
      const s = pick(SITES)
      ev('proxy', base + ri(hm(7, 30), end), { user: u.n, host: u.host, src: u.ip, method: 'GET', domain: s[0], url: '/' + pick(['', 'home', 'api/items']), bytes_out: ri(180, 900), cat: s[1], age: s[2], action: 'allowed' })
    }
    for (let i = 0; i < ri(4, 7); i++) ev('edr', base + ri(hm(7, 30), end), { host: u.host, user: u.n, proc: pick(['outlook.exe', 'chrome.exe', 'tillsoft.exe', 'acrord32.exe']), parent: 'explorer.exe', cmd: 'normal launch', action: 'allowed', sig: 'signed' })
  })
  // ordinary USB use elsewhere
  ev('usb', -86400 + hm(10, 20), { host: 'MKT-PC2', user: 'ned.f', drive: 'E:', vendor: 'SanDisk (company-issued)', action: 'mounted' })
  ev('usb', hm(7, 40), { host: 'FIN-PC1', user: 'liz.t', drive: 'E:', vendor: 'Kingston (company-issued)', action: 'mounted' })

  // The incident
  ev('usb', hm(7, 55, 10), { host: 'SHOP3-PC2', user: 'dan.w', drive: 'E:', vendor: 'GENERIC (not company-issued)', action: 'mounted' }, { key: 'e_usb', tag: 'c1raw' })
  ev('edr', hm(7, 56, 2), { host: 'SHOP3-PC2', user: 'dan.w', proc: 'photos_viewer.exe', parent: 'explorer.exe', cmd: 'E:\\photos_viewer.exe', action: 'allowed', sig: 'unsigned' }, { key: 'e_exec', tag: 'c1raw' })
  ev('edr', hm(7, 56, 9), { host: 'SHOP3-PC2', user: 'dan.w', proc: 'photos_viewer.exe', parent: 'explorer.exe', cmd: 'Trojan.Agent.Gen detected; quarantine FAILED', action: 'detected-quarantine-failed', sig: 'unsigned' }, { key: 'e_av', tag: 'c1raw' })
  for (let i = 0; i < 60; i++) ev('proxy', hm(7, 57, 30) + i * 60, { user: 'dan.w', host: 'SHOP3-PC2', src: U['dan.w'].ip, method: 'POST', domain: C2, url: '/gate.php', bytes_out: 220 + (i % 5) * 3, cat: 'uncategorized', age: 6, action: 'allowed' }, i === 0 ? { key: 'e_beacon' } : {})
  ev('edr', hm(8, 52, 5), { host: 'SHOP3-PC1', user: 'kim.p', proc: 'photos_viewer.exe', parent: 'psexesvc.exe', cmd: 'C:\\Windows\\Temp\\photos_viewer.exe', action: 'allowed', sig: 'unsigned' }, { cond: 'spread', key: 'e_spread', tag: 'c5raw' })

  // Decoys
  ev('edr', hm(8, 1, 14), { host: 'IT-LAP-01', user: 'olu.a', proc: 'eicar.com', parent: 'powershell.exe', cmd: 'EICAR-Test-File detected', action: 'quarantined', sig: 'unsigned' }, { key: 'e_eicar', tag: 'c2raw' })
  ev('proxy', hm(8, 3, 40), { user: 'sue.m', host: 'MKT-PC1', src: U['sue.m'].ip, method: 'POST', domain: 'sendfiles.example', url: '/upload', bytes_out: 182000000, cat: 'file sharing', age: 2400, action: 'allowed' }, { key: 'e_upload', tag: 'c3raw' })
  for (let i = 0; i < 26; i++) ev('entra', hm(8, 2) + i * 24, { user: pick(['admin', 'dan.w', 'bea.s', 'test', 'shop1', 'liz.t', 'sales']), ip: SPRAY, geo: 'Unknown', app: 'Office365 Web', dev: 'none', result: 'failure', mfa: 'n/a' }, i < 3 ? { tag: 'c4raw' } : {})
}))

const ALERTS: Alert[] = [
  { id: 'C1', title: 'AV: Trojan.Agent.Gen detected, quarantine failed', sev: 'high', src: 'EDR', ent: 'SHOP3-PC2', at: hm(8, 0), sla: m(30), raw: 'c1raw',
    rule: 'Malware signature matched and the antivirus could not remove it.',
    kv: [['Host', 'SHOP3-PC2 (dan.w)'], ['File', 'E:\\photos_viewer.exe'], ['Signature', 'unsigned'], ['Result', 'quarantine FAILED']],
    best: 'incident', alt: {}, req: ['e_usb', 'e_av', 'e_beacon'],
    why: 'Dan plugged in a USB stick found in the car park and ran the "photo viewer" on it. The antivirus saw it but could not remove it, and the malware is now beaconing to a command server every minute. This is a real infection that needs the host isolated.',
    hints: ['Where did the program run from? The removable-drive log shows what was plugged in.', 'Is the machine talking to anything odd? Search the proxy for dan.w.'] },
  { id: 'C2', title: 'AV: EICAR test file detected', sev: 'med', src: 'EDR', ent: 'IT-LAP-01', at: hm(8, 5), sla: m(90), raw: 'c2raw',
    rule: 'A known malware test string was seen on disk.',
    kv: [['Host', 'IT-LAP-01 (olu.a, IT)'], ['File', 'eicar.com'], ['Action', 'quarantined']],
    best: 'benign', alt: { fp: 60, it: 60 }, req: ['e_eicar', 'c_ticket'],
    why: 'EICAR is a harmless string every antivirus must detect. IT was testing the new AV policy (CHG-88). The AV did its job and quarantined it. Isolating an IT laptop would have been the wrong move.',
    hints: ['EICAR is a standard test file. Is there a change ticket for AV testing?'] },
  { id: 'C3', title: 'Proxy: 182 MB upload to a file-sharing site', sev: 'med', src: 'Web proxy', ent: 'MKT-PC1', at: hm(8, 10), sla: m(90), raw: 'c3raw',
    rule: 'More than 100 MB sent in one request to a file-sharing category site.',
    kv: [['User', 'sue.m (Marketing)'], ['Destination', 'sendfiles.example'], ['Size', '182 MB'], ['Category', 'file sharing']],
    best: 'benign', alt: { it: 60, fp: 50 }, req: ['e_upload', 'c_ask'],
    why: 'Sue is sending print-ready cover artwork to the printer for the spring campaign. It is big and external, but expected. Ask the person before treating a large upload as data theft.',
    hints: ['Who is Sue and what does she do? Ask IT, or ask her.'] },
  { id: 'C4', title: 'Entra ID: 26 failed sign-ins from one IP', sev: 'low', src: 'Entra ID', ent: SPRAY, at: hm(8, 15), sla: m(120), raw: 'c4raw',
    rule: 'More than 20 failed sign-ins from a single IP in 15 minutes.',
    kv: [['Source IP', SPRAY], ['Window', '08:02 - 08:12'], ['Accounts tried', '7, some not real']],
    best: 'benign', alt: { fp: 50 }, req: ['c_spray'],
    why: 'Background password spraying. The only question that matters is whether anything succeeded, and nothing did. Blocking the IP is a good extra, not an incident.',
    hints: ['Failures are noise. Did any attempt from that IP succeed?'] },
  { id: 'C5', title: 'EDR: same malware now on SHOP3-PC1', sev: 'high', src: 'EDR', ent: 'SHOP3-PC1', at: hm(8, 55), sla: m(30), raw: 'c5raw', late: 'spread',
    rule: 'A program flagged earlier ran on a second machine.',
    kv: [['Host', 'SHOP3-PC1 (kim.p)'], ['Parent', 'psexesvc.exe (remote execution)'], ['File', 'photos_viewer.exe']],
    best: 'incident', alt: {}, req: ['e_spread', 'e_beacon'],
    why: 'Because SHOP3-PC2 was not isolated, the malware used a remote-execution tool to copy itself to the next shop machine. Isolating at the first alert would have stopped this.',
    hints: ['Where did the parent process come from? Compare with C1.'] },
]
const EVD: Record<string, string> = {
  e_usb: 'Unknown USB stick mounted 07:55',
  e_av: 'AV detection with quarantine failed',
  e_beacon: 'Beaconing POSTs to cdn-update-svc.net every minute',
  e_eicar: 'The EICAR detection (quarantined)',
  e_upload: 'The 182 MB upload to sendfiles.example',
  e_spread: 'Malware running on SHOP3-PC1 via psexesvc',
  c_ticket: 'Found the AV-test change ticket',
  c_ask: 'Asked IT or Sue about the upload',
  c_spray: 'Checked whether any attempt from the spray IP succeeded',
}
const TI: Record<string, string> = {
  [C2]: 'Reputation: MALICIOUS · 41 of 90 engines flag it\nCommand-and-control for the Agent.Gen trojan family · first seen 6 days ago',
  [SPRAY]: 'Range seen in ~1,900 abuse reports per day · generic credential-spray botnet · no targeted activity against Tidewater',
  'sendfiles.example': 'Reputation: CLEAN · mainstream file-transfer service used by print shops',
  [SHOP]: 'Tidewater Books corporate egress (internal address)',
}
const WHOIS: Record<string, string> = { [C2]: `Domain:      ${C2}\nCreated:     6 days ago\nRegistrar:   privacy-protected\nNameserver:  bulletproof-dns` }
const PHONE: Record<string, string> = {
  'dan.w': 'Dan W.:\n"I found a USB stick in the car park marked Staff photos, so I plugged it in to see whose it was. A window flashed up and then the PC went slow."',
  'sue.m': 'Sue M.:\n"Yes, that is the spring cover artwork for the printer. It is a huge file so I used their upload link."',
  'olu.a': 'Olu A. (IT):\n"Yes, I am testing the new antivirus policy with an EICAR file. I should have told you."',
  'kim.p': 'Kim P.:\n"I did not do anything. My screen flickered a couple of minutes ago."',
}
const HR: Record<string, string> = { 'dan.w': 'Bookseller · 2 years · no concerns on file.', 'sue.m': 'Marketing manager · spring campaign owner.' }
const TICKET: Record<string, string> = { 'chg-88': 'CHG-88 · Approved · requester olu.a\nScope: test the new AV policy on IT-LAP-01 with the EICAR file\nWindow: 08:00 - 09:00 today' }
function askIT(q: string): string {
  if (/eicar|av\b|antivirus|olu/i.test(q)) return 'IT: Olu is testing the AV policy this morning, see CHG-88.'
  if (/upload|sendfiles|sue|marketing|campaign|artwork/i.test(q)) return 'IT: Marketing has a printer deadline today. They are allowed to use sendfiles.example for artwork.'
  if (/usb|removable/i.test(q)) return 'IT: staff may only use company-issued USB sticks.'
  return 'IT: not sure, can you raise a ticket?'
}
const CONTAIN: Containment[] = [
  { label: 'Isolate SHOP3-PC2', pts: 50, t: (g) => acted(g, 'isolate shop3-pc2') },
  { label: `Block ${C2}`, pts: 40, t: (g) => acted(g, `block-domain ${C2}`) },
  { label: "Reset Dan's password", pts: 30, t: (g) => acted(g, 'reset-password dan.w') },
  { label: 'Take a forensic snapshot of SHOP3-PC2', pts: 20, t: (g) => acted(g, 'snapshot shop3-pc2') },
  { label: 'Block the spray IP', pts: 15, t: (g) => acted(g, `block-ip ${SPRAY}`) },
  { label: 'Isolate SHOP3-PC1 (second infected machine)', pts: 40, t: (g) => acted(g, 'isolate shop3-pc1'), when: (g) => !!g.flags.spread },
]
const WRONG: Wrong[] = [
  { label: 'Isolated IT-LAP-01 (approved AV test)', pts: -50, t: (g) => acted(g, 'isolate it-lap-01') },
  { label: 'Disabled sue.m (approved upload)', pts: -40, t: (g) => acted(g, 'disable-user sue.m') },
  { label: 'Blocked the shop egress IP (outage)', pts: -80, t: (g) => acted(g, `block-ip ${SHOP}`) },
]
const CHECKS: Record<string, (g: GameView) => boolean> = {
  c_ticket: (g) => did(g, /^ticket\s+chg-88/i) || did(g, /^ask-it\s.*(eicar|av|antivirus|olu)/i),
  c_ask: (g) => did(g, /^(phone|hr)\s+sue\.m/i) || did(g, /^ask-it\s.*(upload|sendfiles|sue|marketing)/i),
  c_spray: (g) => did(g, /source=entra/i) && did(g, new RegExp(`(result=success|${SPRAY.replace(/\./g, '\\.')}|stats|top)`, 'i')),
}
function timeline(k: Set<string>, g: GameView): TimelineRow[] {
  const rows: TimelineRow[] = [
    { at: hm(7, 55), text: 'Dan plugs in a USB stick found in the car park', ttp: 'T1091 Replication through removable media', found: k.has('e_usb') },
    { at: hm(7, 56), text: 'He runs "photos_viewer.exe". The AV detects it but cannot remove it', ttp: 'T1204.002 User execution', found: k.has('e_av') },
    { at: hm(7, 57), text: 'The trojan starts beaconing to cdn-update-svc.net once a minute', ttp: 'T1071.001 Web protocols C2', found: k.has('e_beacon') },
  ]
  if (g.flags.spread) rows.push({ at: hm(8, 52), text: 'The malware copies itself to SHOP3-PC1 with a remote-execution tool', ttp: 'T1570 Lateral tool transfer', found: k.has('e_spread') })
  return rows
}
export const shift3: ShiftDef = {
  id: 'soc-3',
  title: 'Tidewater Books: the stick in the car park',
  company: 'Tidewater Books',
  level: 'Starter',
  blurb: 'A found USB stick and a trojan the antivirus could not remove. One real infection, three alerts that only look alarming.',
  intro: 'You are the only analyst covering Tidewater Books, a fictional five-shop bookseller with 90 staff, from 08:00 to 09:30. Four alerts are waiting. Learn to tell malware that is running from a test file or an approved upload.',
  start: hm(8, 0), end: hm(9, 30), dates: ['04-11', '04-12'],
  fields: FIELDS, srcdesc: SRCDESC, users: USERS, build, alerts: ALERTS, evd: EVD,
  intel: { ti: TI, whois: WHOIS, phone: PHONE, badge: {}, hr: HR, tickets: TICKET, askIt: askIT, protectedIps: { [SHOP]: 'this is the shops\' shared egress address. All five tills lose their card machines.' } },
  callable: ['dan.w', 'sue.m', 'olu.a', 'kim.p'],
  triggers: [{
    flag: 'spread', at: hm(8, 50),
    contained: (g) => anyActed(g, 'isolate shop3-pc2'),
    penalty: 70, penaltyLabel: 'Malware spread to a second machine', okLog: 'SHOP3-PC2 isolated before 08:50',
    note: (done, happened) => (!done ? 'The shift ended before the 08:50 deadline.' : happened ? 'The trojan used a remote-execution tool to reach SHOP3-PC1 before you isolated the first machine.' : 'You isolated the first machine before the malware could spread.'),
  }],
  contain: CONTAIN, wrong: WRONG, checks: CHECKS, timeline,
  gaps: ['USB ports were not restricted to company-issued drives.', 'Antivirus could detect but not remove, and nothing alerted a person quickly.', 'The proxy allowed an uncategorised six-day-old domain.', 'Staff could run unsigned programs from removable media.'],
  noteTail: defaultNoteTail,
  chips: ['help', 'source=usb', 'source=proxy user=dan.w | stats count by domain', `ti ${C2}`, 'ticket chg-88'],
  cheat: `source=usb
source=proxy user=dan.w | stats count by domain
source=entra result=success ip=192.0.2.*
ti cdn-update-svc.net     whois some-domain.com
ticket chg-88     phone dan.w     isolate shop3-pc2     help`,
  solution: {
    cmds: ['isolate shop3-pc2', `block-domain ${C2}`, 'reset-password dan.w', 'snapshot shop3-pc2', `block-ip ${SPRAY}`, 'ticket chg-88', 'ask-it marketing upload to sendfiles', 'source=entra result=success ip=192.0.2.*'],
    verdicts: [['C1', 'incident'], ['C2', 'benign'], ['C3', 'benign'], ['C4', 'benign']],
    pins: { C1: ['e_usb', 'e_av', 'e_beacon'], C2: ['e_eicar'], C3: ['e_upload'], C4: [] },
  },
}
