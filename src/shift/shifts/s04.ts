// Shift 4 (Easy): Kestrel Print Works, a fictional commercial printer.
// An exposed RDP port, a brute-forced administrator password, and a ransomware
// crew that waits until morning. The clock on the encryption is the lesson.
import { acted, anyActed, defaultNoteTail, did, eachDay, hm, m, makeScenario, memo, mkUsers } from '../common'
import type { Alert, Containment, GameView, ShiftDef, TimelineRow, Wrong } from '../types'

const ATT = '198.51.100.200'
const SCAN = '192.0.2.77'
const OFFICE = '203.0.113.51'
const NAT = '203.0.113.50'

const FIELDS: Record<string, string> = {
  fw: 'src dst port action bytes',
  winsec: 'host user event src detail',
  edr: 'host user proc parent cmd action sig',
  backup: 'host job result detail',
}
const SRCDESC: Record<string, string> = { fw: 'Perimeter firewall', winsec: 'Windows Security event log (4624 logon, 4625 failed logon, 4720 account created)', edr: 'Endpoint detection (process events)', backup: 'Backup system job log' }

const USERS = mkUsers([
  ['pete.l', 'IT-WS1', 'IT', 'k01'], ['dennis.o', 'OPS-WS1', 'Operations', 'k02'], ['hana.v', 'PRESS-WS1', 'Production', 'k03'], ['carl.j', 'PRESS-WS2', 'Production', 'k04'],
  ['rosa.m', 'DESIGN-WS1', 'Design', 'k05'], ['bill.k', 'DESIGN-WS2', 'Design', 'k06'], ['uma.p', 'SALES-WS1', 'Sales', 'k07'], ['finn.r', 'FIN-WS1', 'Finance', 'k08'],
], 10, 50)

const build = memo(() => makeScenario(20260503, (G) => {
  const { pick, ri, ev } = G
  eachDay(USERS, hm(8, 30), (u, base, end, d) => {
    for (let i = 0; i < ri(2, 3); i++) ev('winsec', base + ri(hm(6, 30), end), { host: u.host, user: u.n, event: '4624', src: u.ip, detail: 'type=2 interactive' })
    for (let i = 0; i < ri(12, 20); i++) ev('fw', base + ri(hm(6, 30), end), { src: u.ip, dst: `203.0.113.${ri(100, 200)}`, port: pick([443, 443, 80, 53]), action: 'allow', bytes: ri(400, 90000) })
    for (let i = 0; i < ri(3, 5); i++) ev('edr', base + ri(hm(6, 30), end), { host: u.host, user: u.n, proc: pick(['indesign.exe', 'chrome.exe', 'outlook.exe', 'rip-client.exe']), parent: 'explorer.exe', cmd: 'normal launch', action: 'allowed', sig: 'signed' })
    void d
  })
  for (const base of [-86400, 0]) {
    for (const h of ['FILE-SRV02', 'PRINT-SRV01', 'DC01']) ev('backup', base + hm(3, 0), { host: h, job: 'nightly', result: base < 0 || h !== 'FILE-SRV02' ? 'OK' : 'FAILED', detail: base < 0 || h !== 'FILE-SRV02' ? 'completed' : 'target volume full (0 GB free)' }, base === 0 && h === 'FILE-SRV02' ? { key: 'e_backupfail', tag: 'd3raw' } : {})
  }
  ev('fw', -86400 + hm(14, 3), { src: SCAN, dst: NAT, port: 22, action: 'deny', bytes: 60 })

  // The intrusion
  for (let i = 0; i < 320; i++) {
    const t = hm(2, 10) + Math.floor(i * (45 * 60) / 320)
    ev('winsec', t, { host: 'PRINT-SRV01', user: pick(['administrator', 'admin', 'print', 'backup', 'administrator']), event: '4625', src: ATT, detail: 'type=10 RDP · bad password' }, i === 0 ? { key: 'e_bruteforce', tag: 'd1raw' } : i < 3 ? { tag: 'd1raw' } : {})
  }
  ev('winsec', hm(2, 57, 14), { host: 'PRINT-SRV01', user: 'administrator', event: '4624', src: ATT, detail: 'type=10 RDP · success' }, { key: 'e_rdp_success', tag: 'd1raw' })
  ev('fw', hm(2, 57, 10), { src: ATT, dst: NAT, port: 3389, action: 'allow', bytes: 48800 })
  ev('winsec', hm(3, 9, 40), { host: 'PRINT-SRV01', user: 'administrator', event: '4720', src: ATT, detail: 'account created: backupadmin, added to Administrators' }, { key: 'e_newuser', tag: 'd2raw' })
  ev('edr', hm(3, 10, 5), { host: 'PRINT-SRV01', user: 'administrator', proc: 'vssadmin.exe', parent: 'cmd.exe', cmd: 'vssadmin delete shadows /all /quiet', action: 'allowed', sig: 'signed' }, { key: 'e_vss', tag: 'd2raw' })
  ev('edr', hm(3, 12, 30), { host: 'PRINT-SRV01', user: 'administrator', proc: 'bcdedit.exe', parent: 'cmd.exe', cmd: 'bcdedit /set {default} recoveryenabled No', action: 'allowed', sig: 'signed' })
  for (let i = 0; i < 40; i++) ev('edr', hm(7, 46) + i * 6, { host: 'PRINT-SRV01', user: 'backupadmin', proc: 'locker.exe', parent: 'cmd.exe', cmd: `locker.exe --encrypt D:\\Jobs\\batch${100 + i} --ext .kestrel`, action: 'allowed', sig: 'unsigned' }, { cond: 'enc', tag: i < 3 ? 'd6raw' : undefined, key: i === 0 ? 'e_enc' : undefined })

  // Decoys
  for (let i = 0; i < 12; i++) ev('winsec', hm(6, 0) + i * 110, { host: 'DC01', user: 'scanner', event: '4625', src: '10.50.7.40', detail: 'type=3 network · bad password (MFP-02)' }, i === 0 ? { key: 'e_mfp', tag: 'd4raw' } : i < 3 ? { tag: 'd4raw' } : {})
  for (let i = 0; i < 30; i++) ev('fw', hm(6, 5) + i * 40, { src: SCAN, dst: NAT, port: 1000 + i * 37, action: 'deny', bytes: 60 }, i < 3 ? { tag: 'd5raw' } : {})
  ev('fw', hm(6, 26), { src: SCAN, dst: NAT, port: 445, action: 'deny', bytes: 60 }, { key: 'e_scan', tag: 'd5raw' })
}))

const ALERTS: Alert[] = [
  { id: 'D1', title: 'Windows: 320 failed RDP logons then a success from one IP', sev: 'high', src: 'Windows Security', ent: 'PRINT-SRV01', at: hm(6, 30), sla: m(30), raw: 'd1raw',
    rule: 'More than 100 failed logons followed by a success from the same source address.',
    kv: [['Host', 'PRINT-SRV01'], ['Source', ATT], ['Window', '02:10 - 02:55'], ['Success', '02:57, user administrator']],
    best: 'incident', alt: {}, req: ['e_bruteforce', 'e_rdp_success'],
    why: 'Someone on the internet brute-forced the administrator password on a print server whose RDP port was open to the world, and got in at 02:57. This alert was waiting for the morning shift.',
    hints: ['Count the failures by source IP, then look at what the same IP did next.'] },
  { id: 'D2', title: 'EDR: shadow copies deleted and backup account created', sev: 'high', src: 'EDR', ent: 'PRINT-SRV01', at: hm(6, 35), sla: m(30), raw: 'd2raw',
    rule: 'vssadmin delete shadows, or a new local administrator, outside a change window.',
    kv: [['Host', 'PRINT-SRV01'], ['Command', 'vssadmin delete shadows /all /quiet'], ['New account', 'backupadmin'], ['Time', '03:09 - 03:12']],
    best: 'incident', alt: {}, req: ['e_vss', 'e_newuser'],
    why: 'Deleting shadow copies and disabling recovery are classic ransomware preparation (T1490), and a new administrator named backupadmin is the attacker\'s way back in. D1 and D2 are one incident, and the encryption has not started yet.',
    hints: ['Who ran it and from which session? Compare with D1.'] },
  { id: 'D3', title: 'Backup: nightly job FAILED on FILE-SRV02', sev: 'med', src: 'Backup', ent: 'FILE-SRV02', at: hm(6, 40), sla: m(120), raw: 'd3raw',
    rule: 'A scheduled backup job finished with a failure.',
    kv: [['Host', 'FILE-SRV02'], ['Job', 'nightly 03:00'], ['Detail', 'target volume full']],
    best: 'it', alt: { benign: 50 }, req: ['e_backupfail', 'c_ask'],
    why: 'The backup target ran out of space. This is a plain IT job, but worth a quick hand-over with the other backups all OK. Isolating a file server would have caused an outage.',
    hints: ['Read the job detail. Is there anything attacker-shaped here, or just a full disk? ask-it can help.'] },
  { id: 'D4', title: 'Windows: 12 failed logons for "scanner" from 10.50.7.40', sev: 'med', src: 'Windows Security', ent: 'DC01', at: hm(6, 28), sla: m(120), raw: 'd4raw',
    rule: 'Repeated failed logons for one account.',
    kv: [['Account', 'scanner (service)'], ['Source', '10.50.7.40 (MFP-02)'], ['Failures', '12 since 06:00']],
    best: 'it', alt: { benign: 60 }, req: ['e_mfp', 'c_ask'],
    why: 'MFP-02 is a multifunction printer still using the old service-account password after Monday\'s rotation. It is not an attack. Hand it to IT to update the saved credential.',
    hints: ['The source is an internal address. What device is it?'] },
  { id: 'D5', title: 'Firewall: port scan from 192.0.2.77', sev: 'low', src: 'Firewall', ent: SCAN, at: hm(6, 32), sla: m(180), raw: 'd5raw',
    rule: 'One source hitting more than 25 different ports within 5 minutes.',
    kv: [['Source', SCAN], ['Action', 'all denied']],
    best: 'benign', alt: { fp: 60 }, req: ['e_scan', 'c_scan'],
    why: 'Internet-wide scanning that the firewall denied. Nothing was allowed through. Blocking it is optional.',
    hints: ['Was any packet from that address allowed?'] },
  { id: 'D6', title: 'EDR: mass file rename to .kestrel on PRINT-SRV01', sev: 'high', src: 'EDR', ent: 'PRINT-SRV01', at: hm(7, 50), sla: m(15), raw: 'd6raw', late: 'enc',
    rule: 'A process renamed more than 50 files with a new extension in one minute.',
    kv: [['Host', 'PRINT-SRV01'], ['Process', 'locker.exe (unsigned)'], ['Extension', '.kestrel']],
    best: 'incident', alt: {}, req: ['e_enc', 'e_vss'],
    why: 'The ransomware ran at 07:46, after the attacker waited for the workday. Isolating PRINT-SRV01 after the first alerts would have stopped it before a single job file was encrypted.',
    hints: ['This is what D2 was warning about.'] },
]
const EVD: Record<string, string> = {
  e_bruteforce: 'The brute-force failures from the attacker IP',
  e_rdp_success: 'The successful RDP logon at 02:57',
  e_newuser: 'backupadmin account created 03:09',
  e_vss: 'Shadow copies deleted 03:10',
  e_backupfail: 'Backup failure detail: target volume full',
  e_mfp: 'The scanner failures come from MFP-02',
  e_scan: 'Denied scan events',
  e_enc: 'locker.exe renaming files to .kestrel',
  c_ask: 'Asked IT what the device or failure was',
  c_scan: 'Checked whether any scan traffic was allowed',
}
const TI: Record<string, string> = {
  [ATT]: 'AS64502 BulkVPS GmbH · hosting range · 61 abuse reports (RDP brute force)\nLinked to a ransomware affiliate that deletes shadow copies before encrypting\nReputation: MALICIOUS',
  [SCAN]: 'Range seen in ~1,900 abuse reports per day · generic internet scanner · no targeted activity against Kestrel',
  [OFFICE]: 'Kestrel Print Works office egress (internal address)',
  [NAT]: 'Kestrel Print Works public address (NAT for PRINT-SRV01 remote desktop)',
}
const PHONE: Record<string, string> = {
  'pete.l': 'Pete L. (IT):\n"The print server RDP port was opened for the RIP vendor months ago and I never closed it. Nobody should be logged on there at 3am. I did not create a backupadmin account."',
  'dennis.o': 'Dennis O. (Operations):\n"Nobody on my team works the print server overnight. Tell me if production is at risk, the Jenkins brochure run starts at 08:00."',
}
const HR: Record<string, string> = { 'pete.l': 'IT Manager · on call this week.', 'dennis.o': 'Operations Manager.' }
const TICKET: Record<string, string> = { 'tkt-4021': 'TKT-4021 · Open · FILE-SRV02 backup volume at 98% since Friday. Awaiting disk purchase.' }
function askIT(q: string): string {
  if (/mfp|scanner|printer|10\.50\.7\.40/i.test(q)) return 'IT: MFP-02 was swapped on Monday and the scan-to-folder account password was rotated. The new device still has the old one.'
  if (/backup|file-srv|disk|volume|full/i.test(q)) return 'IT: FILE-SRV02 backup volume is nearly full, see TKT-4021. Other backups are fine.'
  if (/rdp|print-srv|3389/i.test(q)) return 'IT: RDP to PRINT-SRV01 was opened for the RIP vendor. It should have been closed.'
  return 'IT: not sure, can you raise a ticket?'
}
const CONTAIN: Containment[] = [
  { label: 'Isolate PRINT-SRV01', pts: 60, t: (g) => acted(g, 'isolate print-srv01') },
  { label: `Block ${ATT}`, pts: 30, t: (g) => acted(g, `block-ip ${ATT}`) },
  { label: 'Reset the administrator password', pts: 30, t: (g) => acted(g, 'reset-password administrator') },
  { label: 'Delete the backupadmin account', pts: 30, t: (g) => acted(g, 'delete-account backupadmin') },
  { label: 'Take a forensic snapshot of PRINT-SRV01', pts: 20, t: (g) => acted(g, 'snapshot print-srv01') },
  { label: 'Tell the incident-response lead', pts: 15, t: (g) => acted(g, 'notify ir-lead') },
  { label: 'Block the scanner IP', pts: 10, t: (g) => acted(g, `block-ip ${SCAN}`) },
]
const WRONG: Wrong[] = [
  { label: 'Isolated FILE-SRV02 (full backup disk)', pts: -60, t: (g) => acted(g, 'isolate file-srv02') },
  { label: 'Disabled the scanner account (breaks scanning for everyone)', pts: -30, t: (g) => acted(g, 'disable-user scanner') },
  { label: 'Blocked the office egress IP (outage)', pts: -80, t: (g) => acted(g, `block-ip ${OFFICE}`) },
  { label: 'Deleted files on PRINT-SRV01 (destroys evidence)', pts: -40, t: (g) => [...g.actions].some((x) => x.startsWith('delete-file print-srv01')) },
]
const CHECKS: Record<string, (g: GameView) => boolean> = {
  c_ask: (g) => did(g, /^ask-it\s.*(mfp|scanner|printer|backup|file-srv|disk|volume)/i) || did(g, /^ticket\s+tkt-4021/i),
  c_scan: (g) => did(g, /source=fw/i) && did(g, /(action=allow|stats|top|dedup)/i),
}
function timeline(k: Set<string>, g: GameView): TimelineRow[] {
  const rows: TimelineRow[] = [
    { at: hm(2, 10), text: 'Brute-force of the RDP port on PRINT-SRV01 begins', ttp: 'T1110 Brute force', found: k.has('e_bruteforce') },
    { at: hm(2, 57), text: 'Attacker logs on as administrator', ttp: 'T1133 External remote services / T1078', found: k.has('e_rdp_success') },
    { at: hm(3, 9), text: 'Creates backupadmin, deletes shadow copies, disables recovery', ttp: 'T1136.001 / T1490 Inhibit system recovery', found: k.has('e_vss') || k.has('e_newuser') },
  ]
  if (g.flags.enc) rows.push({ at: hm(7, 46), text: 'locker.exe encrypts the job files on PRINT-SRV01', ttp: 'T1486 Data encrypted for impact', found: k.has('e_enc') })
  return rows
}
export const shift4: ShiftDef = {
  id: 'soc-4',
  title: 'Kestrel Print Works: before the presses start',
  company: 'Kestrel Print Works',
  level: 'Easy',
  blurb: 'An internet-exposed RDP port, a brute-forced password and ransomware preparation. You have until 07:45 to act.',
  intro: 'You are the morning analyst at Kestrel Print Works, a fictional commercial printer with 140 staff, from 06:30 to 08:30. The night shift left a queue. The production line starts at 08:00. Work out which alerts belong together, and act before anything is encrypted.',
  start: hm(6, 30), end: hm(8, 30), dates: ['05-02', '05-03'],
  fields: FIELDS, srcdesc: SRCDESC, users: USERS, build, alerts: ALERTS, evd: EVD,
  intel: { ti: TI, whois: {}, phone: PHONE, badge: {}, hr: HR, tickets: TICKET, askIt: askIT, protectedIps: { [OFFICE]: 'this is the office egress address. The whole site loses internet access.' } },
  callable: ['pete.l', 'dennis.o'],
  triggers: [{
    flag: 'enc', at: hm(7, 45),
    contained: (g) => anyActed(g, 'isolate print-srv01'),
    penalty: 120, penaltyLabel: 'Ransomware encrypted PRINT-SRV01', okLog: 'PRINT-SRV01 isolated before 07:45',
    note: (done, happened) => (!done ? 'The shift ended before the 07:45 deadline.' : happened ? 'The ransomware ran at 07:46 because PRINT-SRV01 was still on the network.' : 'You isolated the print server before the ransomware ran.'),
  }],
  contain: CONTAIN, wrong: WRONG, checks: CHECKS, timeline,
  gaps: ['RDP was open to the internet with no VPN or MFA.', 'The administrator account had no lockout policy for repeated failures.', 'Shadow-copy deletion did not page anyone overnight.', 'No out-of-hours on-call for high-severity alerts.'],
  noteTail: defaultNoteTail,
  chips: ['help', 'source=winsec event=4625 | stats count by src', 'source=winsec src=198.51.100.200 event!=4625', 'source=edr host=PRINT-SRV01 | sort time', `ti ${ATT}`],
  cheat: `source=winsec event=4625 | stats count by src
source=winsec src=198.51.100.200 event!=4625
source=edr host=PRINT-SRV01 | sort time
source=fw src=192.0.2.77 action=allow
ti 198.51.100.200     ask-it mfp scanner     isolate print-srv01     help`,
  solution: {
    cmds: ['isolate print-srv01', `block-ip ${ATT}`, 'reset-password administrator', 'delete-account backupadmin', 'snapshot print-srv01', 'notify ir-lead', 'ask-it backup full', 'ask-it mfp scanner', `block-ip ${SCAN}`, 'source=fw src=192.0.2.77 action=allow'],
    verdicts: [['D1', 'incident'], ['D2', 'incident'], ['D3', 'it'], ['D4', 'it'], ['D5', 'benign']],
    pins: { D1: ['e_bruteforce', 'e_rdp_success'], D2: ['e_vss', 'e_newuser'], D3: ['e_backupfail'], D4: ['e_mfp'], D5: ['e_scan'] },
  },
}
