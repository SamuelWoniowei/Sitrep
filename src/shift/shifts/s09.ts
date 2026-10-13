// Shift 9 (Expert): Halden Energy, a fictional regional power utility.
// A dormant contractor account, Kerberoasting, an over-privileged service
// account, DCSync, a ten-year ticket, DNS command-and-control and a staged
// historian database. Two clocks are running (09:30 and 10:15). Normal domain
// controller traffic and a SQL failover look nearly identical to the attack.
import { acted, anyActed, defaultNoteTail, did, eachDay, hm, m, makeScenario, memo, mkUsers } from '../common'
import type { Alert, Containment, GameView, ShiftDef, TimelineRow, Wrong } from '../types'

const ATT = '198.51.100.180'
const OFFICE = '203.0.113.100'
const C2 = 'metrics-collect.net'
const JUMP = '10.80.4.22'
const HIST = '10.80.6.30'

const FIELDS: Record<string, string> = {
  winsec: 'host user event src detail',
  edr: 'host user proc parent cmd action sig',
  dns: 'host qname qtype answer',
  vpn: 'ip user result reason geo',
  fw: 'src dst port action bytes',
}
const SRCDESC: Record<string, string> = {
  winsec: 'Domain controller and server Security log (4624 logon, 4662 directory access, 4720 account created, 4728 group add, 4769 Kerberos service ticket)',
  edr: 'Endpoint detection (process events)',
  dns: 'Internal DNS resolver log',
  vpn: 'VPN gateway',
  fw: 'Perimeter and OT-boundary firewall',
}

const USERS = mkUsers([
  ['mel.d', 'IT-WS-01', 'IT', 'q01'], ['pri.k', 'OT-WS-01', 'OT Engineering', 'q02'], ['hal.j', 'HELP-WS-01', 'Helpdesk', 'q03'], ['tom.e', 'OPS-WS-02', 'Operations', 'q04'],
  ['ines.b', 'FIN-WS-03', 'Finance', 'q05'], ['kofi.a', 'OT-WS-02', 'OT Engineering', 'q06'], ['rae.l', 'IT-WS-03', 'IT', 'q07'], ['c.dunn', 'JUMP-02', 'Contractor', 'q08'],
  ['svc-hist', 'HIST-DB01', 'Service', 'q09'], ['svc-sql', 'DB-SRV01', 'Service', 'q10'], ['svc-backup', 'BKP-SRV01', 'Service', 'q11'],
], 10, 110)

const build = memo(() => makeScenario(20260915, (G) => {
  const { R, pick, ri, ev } = G
  const human = USERS.filter((u) => u.dept !== 'Service' && u.n !== 'c.dunn')
  eachDay(human, hm(11, 0), (u, base, end) => {
    for (let i = 0; i < ri(2, 4); i++) ev('winsec', base + ri(hm(6, 30), end), { host: u.host, user: u.n, event: '4624', src: u.ip, detail: 'type=2 interactive' })
    for (let i = 0; i < ri(2, 4); i++) ev('winsec', base + ri(hm(6, 30), end), { host: 'DC01', user: u.n, event: '4769', src: u.ip, detail: `service=${pick(['cifs/fileserver', 'http/intranet', 'ldap/dc01'])} etype=0x12 (AES256)` })
    for (let i = 0; i < ri(14, 24); i++) ev('dns', base + ri(hm(6, 30), end), { host: u.host, qname: pick(['intranet.halden.example', 'update.microsoft.example', 'www.bbc.co.uk', 'mail.halden.example', 'time.windows.example']), qtype: 'A', answer: 'ok' })
    for (let i = 0; i < ri(3, 5); i++) ev('edr', base + ri(hm(6, 30), end), { host: u.host, user: u.n, proc: pick(['outlook.exe', 'chrome.exe', 'scada-viewer.exe', 'teams.exe']), parent: 'explorer.exe', cmd: 'normal launch', action: 'allowed', sig: 'signed' })
  })
  for (const base of [-86400, 0]) {
    const end = base < 0 ? hm(23, 59) : hm(11, 0)
    for (let t = hm(0, 7); t < end; t += 900) ev('winsec', base + t, { host: 'DC01', user: 'DC02$', event: '4662', src: '10.80.1.12', detail: 'Replicating Directory Changes (domain controller to domain controller)' }, base === 0 && t >= hm(8, 0) && t < hm(8, 15) ? { key: 'e_dc02', tag: 'i4raw' } : {})
    ev('edr', base + hm(3, 0), { host: 'HIST-DB01', user: 'svc-backup', proc: '7z.exe', parent: 'taskeng.exe', cmd: '7z.exe a D:\\Backups\\hist_nightly.7z D:\\Historian\\*', action: 'allowed', sig: 'signed' }, base === 0 ? { key: 'e_nightly7z', tag: 'i7raw' } : {})
    for (let i = 0; i < 6; i++) ev('vpn', base + hm(7, 30) + i * 1900, { ip: `203.0.113.${150 + i}`, user: pick(['mel.d', 'pri.k', 'kofi.a', 'rae.l']), result: 'success', reason: 'mfa satisfied', geo: 'GB' })
    for (let i = 0; i < 10; i++) ev('fw', base + hm(8, 0) + i * 3000, { src: HIST, dst: '10.80.9.9', port: 4840, action: 'allow', bytes: ri(2000, 90000) })
  }

  // The attack chain
  ev('vpn', -86400 + hm(21, 30, 12), { ip: ATT, user: 'c.dunn', result: 'success', reason: 'mfa satisfied (SMS)', geo: 'RO' }, { key: 'e_vpn', tag: 'i1raw' })
  const targets = ['svc-sql', 'svc-hist', 'svc-backup', 'svc-scada-gw', 'svc-print', 'svc-web', 'svc-mon', 'svc-ftp']
  for (let i = 0; i < 14; i++) ev('winsec', -86400 + hm(21, 48, 5) + i, { host: 'DC01', user: 'c.dunn', event: '4769', src: JUMP, detail: `service=mssql/${targets[i % targets.length]} etype=0x17 (RC4)` }, i === 0 ? { key: 'e_kerb', tag: 'i2raw' } : i < 3 ? { tag: 'i2raw' } : {})
  ev('winsec', -86400 + hm(22, 20, 40), { host: 'JUMP-02', user: 'svc-hist', event: '4624', src: JUMP, detail: 'type=3 network · first logon from a jump host' }, { key: 'e_svc_logon' })
  ev('winsec', -86400 + hm(22, 41, 7), { host: 'DC01', user: 'svc-hist', event: '4662', src: JUMP, detail: 'Replicating Directory Changes All from JUMP-02 (not a domain controller)' }, { key: 'e_dcsync', tag: 'i3raw' })
  ev('winsec', -86400 + hm(22, 41, 9), { host: 'DC01', user: 'svc-hist', event: '4662', src: JUMP, detail: 'Replicating Directory Changes All: attribute unicodePwd / krbtgt' }, { tag: 'i3raw' })
  ev('winsec', hm(2, 15, 30), { host: 'DC01', user: 'administrator', event: '4769', src: JUMP, detail: 'service=krbtgt/halden ticket lifetime 87600h (10 years) · no preceding TGT request' }, { key: 'e_golden' })
  for (let i = 0; i < 320; i++) ev('dns', -86400 + hm(22, 30) + i * 160, { host: 'JUMP-02', qname: `${Math.floor(R() * 1e12).toString(16).padStart(24, 'a')}.${C2}`, qtype: 'TXT', answer: 'ok' }, i === 0 ? { key: 'e_dns', tag: 'i6raw' } : i < 3 ? { tag: 'i6raw' } : {})
  ev('edr', hm(7, 10, 22), { host: 'HIST-DB01', user: 'administrator', proc: '7z.exe', parent: 'wmiprvse.exe', cmd: '7z.exe a C:\\ProgramData\\h.7z D:\\Historian\\* -p', action: 'allowed', sig: 'signed' }, { key: 'e_stage', tag: 'i9raw' })
  ev('winsec', hm(7, 8, 41), { host: 'HIST-DB01', user: 'administrator', event: '4624', src: JUMP, detail: 'type=3 network · Kerberos (ticket from the 10-year TGT)' }, { tag: 'i9raw' })
  for (let i = 0; i < 12; i++) ev('fw', hm(9, 31) + i * 70, { src: HIST, dst: ATT, port: 443, action: 'allow', bytes: 380000000 + i * 2000000 }, { cond: 'exfil', key: i === 0 ? 'e_exfil' : undefined, tag: i < 3 ? 'i10raw' : undefined })
  ev('winsec', hm(10, 16, 4), { host: 'DC01', user: 'administrator', event: '4720', src: JUMP, detail: 'account created: ops.admin2' }, { cond: 'persist', key: 'e_persist', tag: 'i11raw' })
  ev('winsec', hm(10, 16, 20), { host: 'DC01', user: 'administrator', event: '4728', src: JUMP, detail: 'ops.admin2 added to Domain Admins' }, { cond: 'persist', tag: 'i11raw' })

  // Decoys
  ev('winsec', hm(8, 12, 30), { host: 'DB-SRV02', user: 'svc-sql', event: '4624', src: '10.80.6.41', detail: 'type=3 network · first logon from DB-SRV02 (failover node)' }, { key: 'e_sqlfo', tag: 'i5raw' })
  ev('winsec', -86400 + hm(10, 0), { host: 'DB-SRV01', user: 'svc-sql', event: '4624', src: '10.80.6.40', detail: 'type=3 network · from DB-SRV01' })
}))

const ALERTS: Alert[] = [
  { id: 'I1', title: 'VPN: contractor c.dunn signed in from a new country (Romania)', sev: 'low', src: 'VPN', ent: 'c.dunn', at: hm(8, 0), sla: m(60), raw: 'i1raw',
    rule: 'A VPN sign-in from a country not seen for the account in 90 days.',
    kv: [['User', 'c.dunn (contractor)'], ['Source', `${ATT} (RO)`], ['MFA', 'SMS code'], ['Time', 'Yesterday 21:30']],
    best: 'incident', alt: {}, req: ['e_vpn', 'c_dormant'],
    why: 'c.dunn\'s contract ended on 08-30 and the account should have been disabled. A dormant contractor account signed in from a hosting IP in Romania using SMS MFA (which can be intercepted or socially engineered). This is the entry point.',
    hints: ['Check HR for the contractor\'s status.', 'What did the account do after signing in?'] },
  { id: 'I2', title: 'Kerberos: 14 RC4 service tickets in 14 seconds by one user', sev: 'med', src: 'Windows Security', ent: 'c.dunn', at: hm(8, 0), sla: m(60), raw: 'i2raw',
    rule: 'One account requested more than 10 service tickets using RC4 encryption in a minute.',
    kv: [['User', 'c.dunn'], ['Host', 'JUMP-02'], ['Services', 'svc-sql, svc-hist, svc-backup and 5 more'], ['Encryption', '0x17 (RC4)']],
    best: 'incident', alt: {}, req: ['e_kerb', 'e_vpn'],
    why: 'Kerberoasting (T1558.003): ask for tickets for every service account, take them away and crack them offline. Normal users get AES tickets for one or two services, not a sweep of every service account.',
    hints: ['Compare with how c.dunn and others normally request tickets: the etype and the count.'] },
  { id: 'I3', title: 'AD: directory replication rights used by svc-hist from JUMP-02', sev: 'high', src: 'Windows Security', ent: 'svc-hist', at: hm(8, 10), sla: m(30), raw: 'i3raw',
    rule: 'Replicating Directory Changes All performed by an account that is not a domain controller.',
    kv: [['Account', 'svc-hist (historian service)'], ['Source', `JUMP-02 (${JUMP})`], ['Target', 'DC01'], ['Time', 'Yesterday 22:41']],
    best: 'incident', alt: {}, req: ['e_dcsync', 'e_svc_logon'],
    why: 'DCSync (T1003.006): the account copied every password hash in the domain, including krbtgt, by pretending to be a domain controller. svc-hist can do that because it was put in Domain Admins "for convenience". It was cracked after the Kerberoast.',
    hints: ['Who is allowed to replicate the directory? Compare with I4.', 'What was svc-hist\'s first logon from JUMP-02?'] },
  { id: 'I4', title: 'AD: directory replication request by DC02$', sev: 'med', src: 'Windows Security', ent: 'DC02$', at: hm(8, 5), sla: m(90), raw: 'i4raw',
    rule: 'Any use of directory replication rights (event 4662).',
    kv: [['Account', 'DC02$ (domain controller computer account)'], ['Target', 'DC01'], ['Frequency', 'every 15 minutes']],
    best: 'benign', alt: { fp: 70 }, req: ['e_dc02', 'c_dcs'],
    why: 'Normal domain-controller-to-domain-controller replication, every 15 minutes, all day. Same event ID as I3 and very different meaning: the source is a real DC. Isolating a DC would have taken authentication down for the whole utility.',
    hints: ['Is DC02 a domain controller? Are these requests regular?'] },
  { id: 'I5', title: 'Windows: svc-sql logged on from a new host (DB-SRV02)', sev: 'med', src: 'Windows Security', ent: 'svc-sql', at: hm(8, 15), sla: m(90), raw: 'i5raw',
    rule: 'A service account logged on from a host it has never used.',
    kv: [['Account', 'svc-sql'], ['Source', 'DB-SRV02 (10.80.6.41)'], ['Time', 'Today 08:12']],
    best: 'benign', alt: { it: 60, fp: 50 }, req: ['e_sqlfo', 'c_sqlfo'],
    why: 'The SQL cluster failed over to DB-SRV02 (change CHG-SQLFO). svc-sql was one of the Kerberoasted accounts, so it is worth a look, but the logon came from a known DB node during a planned change. Disabling it would have stopped the databases.',
    hints: ['svc-sql was in the Kerberoast list. Does this logon come from the attacker\'s host or from the database team?'] },
  { id: 'I6', title: 'DNS: 320 long random TXT queries to metrics-collect.net from JUMP-02', sev: 'low', src: 'DNS', ent: 'JUMP-02', at: hm(8, 30), sla: m(120), raw: 'i6raw',
    rule: 'More than 100 queries with random-looking labels to one domain.',
    kv: [['Host', 'JUMP-02'], ['Domain', C2], ['Type', 'TXT'], ['Rate', 'one every 2-3 minutes since 22:30']],
    best: 'incident', alt: {}, req: ['e_dns'],
    why: 'DNS tunnelling (T1071.004), the attacker\'s command-and-control channel from JUMP-02. It is slow and quiet by design. It also shows JUMP-02 is the attacker\'s base.',
    hints: ['Look up the domain. Which host is making these requests?'] },
  { id: 'I7', title: 'EDR: 7-Zip archiving D:\\Historian on HIST-DB01 (svc-backup)', sev: 'low', src: 'EDR', ent: 'HIST-DB01', at: hm(8, 20), sla: m(120), raw: 'i7raw',
    rule: '7z.exe compressing the historian data directory.',
    kv: [['Host', 'HIST-DB01'], ['User', 'svc-backup'], ['Parent', 'taskeng.exe'], ['Output', 'D:\\Backups\\hist_nightly.7z'], ['Time', '03:00']],
    best: 'benign', alt: { fp: 60 }, req: ['e_nightly7z', 'c_nightly'],
    why: 'The scheduled nightly backup, run at 03:00 every night by svc-backup from the task scheduler into D:\\Backups. It looks like I9 but is a different user, parent and output path.',
    hints: ['Search edr for 7z.exe and compare the user, parent and output path across days.'] },
  { id: 'I9', title: 'EDR: password-protected 7z of D:\\Historian by an interactive admin session', sev: 'high', src: 'EDR', ent: 'HIST-DB01', at: hm(8, 45), sla: m(30), raw: 'i9raw',
    rule: 'Compression of a sensitive data directory with a password option.',
    kv: [['Host', 'HIST-DB01'], ['User', 'administrator'], ['Parent', 'wmiprvse.exe (remote WMI)'], ['Output', 'C:\\ProgramData\\h.7z -p'], ['Time', '07:10']],
    best: 'incident', alt: {}, req: ['e_stage', 'e_golden'],
    why: 'Data staged for exfiltration (T1560.001). The administrator logon behind it uses a ticket with a ten-year lifetime and no TGT request: a golden ticket (T1558.001) built from the krbtgt hash stolen by DCSync. A password reset of the administrator will not help; krbtgt must be reset.',
    hints: ['Who ran it, from which logon, and what is odd about that ticket?', 'The attacker now has the krbtgt hash.'] },
  { id: 'I10', title: 'Firewall: 4.6 GB outbound from HIST-DB01 to a rare destination', sev: 'high', src: 'Firewall', ent: 'HIST-DB01', at: hm(9, 50), sla: m(15), raw: 'i10raw', late: 'exfil',
    rule: 'More than 1 GB sent from an OT-adjacent server to an address it has never contacted.',
    kv: [['Source', `HIST-DB01 (${HIST})`], ['Destination', `${ATT}:443`], ['Volume', '4.6 GB over 14 minutes']],
    best: 'incident', alt: {}, req: ['e_exfil', 'e_stage'],
    why: 'The staged archive left the network at 09:31. Isolating HIST-DB01 or blocking the attacker IP before 09:30 would have stopped it. Operational plant data and network diagrams for a utility are valuable to a state or criminal actor.',
    hints: ['This is the archive from I9 leaving.'] },
  { id: 'I11', title: 'AD: new Domain Admin ops.admin2 created by administrator', sev: 'high', src: 'Windows Security', ent: 'ops.admin2', at: hm(10, 25), sla: m(15), raw: 'i11raw', late: 'persist',
    rule: 'A new account added to Domain Admins outside a change window.',
    kv: [['Created by', 'administrator (from JUMP-02)'], ['Account', 'ops.admin2'], ['Group', 'Domain Admins']],
    best: 'incident', alt: {}, req: ['e_persist', 'e_golden'],
    why: 'The attacker, still holding a golden ticket, created a new Domain Admin for lasting access. Resetting krbtgt before 10:15 would have invalidated the golden ticket and made this impossible.',
    hints: ['A golden ticket is valid until krbtgt changes.'] },
]
const EVD: Record<string, string> = {
  e_vpn: 'c.dunn VPN sign-in from Romania',
  e_kerb: '14 RC4 service-ticket requests in 14 seconds',
  e_svc_logon: "svc-hist's first logon from JUMP-02",
  e_dcsync: 'DCSync from JUMP-02 (not a DC)',
  e_golden: 'Ticket with a 10-year lifetime for administrator',
  e_dns: 'Random TXT queries to metrics-collect.net',
  e_stage: 'Password-protected 7z of D:\\Historian by administrator',
  e_exfil: '4.6 GB outbound to the attacker IP',
  e_persist: 'ops.admin2 created and added to Domain Admins',
  e_dc02: 'Regular DC02$ replication every 15 minutes',
  e_sqlfo: 'svc-sql logon from DB-SRV02 (failover)',
  e_nightly7z: 'The 03:00 nightly svc-backup archive',
  c_dormant: 'Checked HR or IT on whether c.dunn should still exist',
  c_dcs: 'Confirmed DC02 is a domain controller or compared replication sources',
  c_sqlfo: 'Found the SQL failover change',
  c_nightly: 'Compared the 7z runs across users or days',
}
const TI: Record<string, string> = {
  [ATT]: 'AS64506 TransitPoint SRL · Bucharest, RO · hosting range\nTied to a state-linked group targeting energy and water operators (public reporting)\nReputation: MALICIOUS',
  [C2]: 'Reputation: MALICIOUS · registered 12 days ago\nDNS-tunnelling C2 (long TXT labels), same family as the group above',
  [OFFICE]: 'Halden Energy corporate egress (internal address)',
}
const WHOIS: Record<string, string> = { [C2]: `Domain:      ${C2}\nCreated:     12 days ago\nRegistrar:   privacy-protected\nNameserver:  custom (single IP in RO)` }
const PHONE: Record<string, string> = {
  'mel.d': 'Mel D. (IT):\n"c.dunn\'s contract ended on the 30th. The offboarding ticket was never actioned, so the account is still enabled. I am so sorry."',
  'pri.k': 'Priya K. (OT):\n"svc-hist is the historian service account. It should be a local admin on HIST-DB01 only. Why is it in Domain Admins?" She checks. "It was added in 2021 to fix a permissions problem."',
  'hal.j': 'Hal J. (Helpdesk):\n"I did not touch c.dunn. And no, I did not reset any passwords this morning."',
}
const HR: Record<string, string> = {
  'c.dunn': 'External contractor (Redwater Systems) · CONTRACT ENDED 08-30 · account should have been removed.',
  'svc-hist': 'Service account, owner: OT Engineering. Approved scope: local admin on HIST-DB01.',
}
const TICKET: Record<string, string> = { 'chg-sqlfo': 'CHG-SQLFO · Approved · requester kofi.a\nScope: planned failover of the SQL cluster from DB-SRV01 to DB-SRV02\nWindow: 08:00 - 09:00 today\nNote: svc-sql will log on from DB-SRV02.' }
function askIT(q: string): string {
  if (/dc02|replic|domain controller|\bdc\b/i.test(q)) return 'IT: DC01 and DC02 are the two domain controllers. They replicate every 15 minutes.'
  if (/sql|failover|svc-sql|db-srv/i.test(q)) return 'IT: the SQL cluster fails over to DB-SRV02 this morning, see CHG-SQLFO.'
  if (/backup|7z|nightly/i.test(q)) return 'IT: svc-backup archives the historian every night at 03:00 into D:\\Backups.'
  return 'IT: not sure, can you raise a ticket?'
}
const CONTAIN: Containment[] = [
  { label: 'Reset krbtgt (kills golden tickets)', pts: 60, t: (g) => acted(g, 'reset-password krbtgt') },
  { label: 'Isolate JUMP-02 (attacker base)', pts: 40, t: (g) => acted(g, 'isolate jump-02') },
  { label: 'Isolate HIST-DB01 (staged data)', pts: 40, t: (g) => acted(g, 'isolate hist-db01') },
  { label: 'Disable the dormant contractor account c.dunn', pts: 30, t: (g) => acted(g, 'disable-user c.dunn') },
  { label: 'Reset the svc-hist password', pts: 30, t: (g) => acted(g, 'reset-password svc-hist') },
  { label: 'Remove svc-hist from Domain Admins', pts: 30, t: (g) => acted(g, 'remove-group svc-hist domain admins') },
  { label: `Block ${ATT}`, pts: 20, t: (g) => acted(g, `block-ip ${ATT}`) },
  { label: `Block ${C2}`, pts: 20, t: (g) => acted(g, `block-domain ${C2}`) },
  { label: 'Snapshot JUMP-02 for forensics', pts: 20, t: (g) => acted(g, 'snapshot jump-02') },
  { label: 'Tell the incident-response lead', pts: 15, t: (g) => acted(g, 'notify ir-lead') },
  { label: 'Tell management and legal (reportable incident at a utility)', pts: 25, t: (g) => acted(g, 'notify management') && acted(g, 'notify legal'), when: (g) => !!g.flags.exfil },
  { label: 'Delete the rogue ops.admin2 account', pts: 30, t: (g) => acted(g, 'delete-account ops.admin2'), when: (g) => !!g.flags.persist },
]
const WRONG: Wrong[] = [
  { label: 'Isolated a domain controller (authentication outage)', pts: -100, t: (g) => acted(g, 'isolate dc01') || acted(g, 'isolate dc02') },
  { label: 'Disabled svc-sql (database outage during failover)', pts: -50, t: (g) => acted(g, 'disable-user svc-sql') },
  { label: 'Disabled svc-backup (backups stop)', pts: -50, t: (g) => acted(g, 'disable-user svc-backup') },
  { label: 'Isolated DB-SRV02 (planned failover node)', pts: -50, t: (g) => acted(g, 'isolate db-srv02') },
  { label: 'Blocked the corporate egress IP (outage)', pts: -80, t: (g) => acted(g, `block-ip ${OFFICE}`) },
]
const CHECKS: Record<string, (g: GameView) => boolean> = {
  c_dormant: (g) => did(g, /^(hr|phone)\s+(c\.dunn|mel\.d)/i),
  c_dcs: (g) => did(g, /^ask-it\s.*(dc02|replic|domain controller|\bdc\b)/i) || (did(g, /source=winsec.*event=4662/i) && did(g, /(stats|top|dedup)/i)),
  c_sqlfo: (g) => did(g, /^ticket\s+chg-sqlfo/i) || did(g, /^ask-it\s.*(sql|failover|svc-sql)/i),
  c_nightly: (g) => did(g, /source=edr.*(7z|proc=7z)/i) || did(g, /^ask-it\s.*(backup|7z|nightly)/i),
}
function timeline(k: Set<string>, g: GameView): TimelineRow[] {
  const rows: TimelineRow[] = [
    { at: -86400 + hm(21, 30), text: 'Dormant contractor account c.dunn signs in over VPN from Romania', ttp: 'T1078 Valid accounts / T1133', found: k.has('e_vpn') },
    { at: -86400 + hm(21, 48), text: 'Kerberoast: RC4 tickets for every service account', ttp: 'T1558.003 Kerberoasting', found: k.has('e_kerb') },
    { at: -86400 + hm(22, 20), text: 'svc-hist (cracked offline, Domain Admin) logs on from JUMP-02', ttp: 'T1078.002 Domain accounts', found: k.has('e_svc_logon') },
    { at: -86400 + hm(22, 41), text: 'DCSync copies every hash in the domain, including krbtgt', ttp: 'T1003.006 DCSync', found: k.has('e_dcsync') },
    { at: -86400 + hm(22, 30), text: 'DNS tunnelling C2 from JUMP-02 begins', ttp: 'T1071.004 DNS', found: k.has('e_dns') },
    { at: hm(2, 15), text: 'A golden ticket for administrator is used', ttp: 'T1558.001 Golden ticket', found: k.has('e_golden') },
    { at: hm(7, 10), text: 'The historian data directory is compressed with a password', ttp: 'T1560.001 Archive collected data', found: k.has('e_stage') },
  ]
  if (g.flags.exfil) rows.push({ at: hm(9, 31), text: '4.6 GB archive leaves for the attacker IP', ttp: 'T1041 Exfiltration over C2 channel', found: k.has('e_exfil') })
  if (g.flags.persist) rows.push({ at: hm(10, 16), text: 'ops.admin2 is created as a new Domain Admin', ttp: 'T1136.002 Create domain account', found: k.has('e_persist') })
  return rows
}
export const shift9: ShiftDef = {
  id: 'soc-9',
  title: 'Halden Energy: the golden ticket',
  company: 'Halden Energy',
  level: 'Expert',
  blurb: 'A dormant contractor account, Kerberoasting, DCSync and a ten-year ticket. Normal domain-controller traffic looks identical to the attack. Two deadlines.',
  intro: 'You are the senior analyst at Halden Energy, a fictional regional power utility, from 08:00 to 11:00. The queue is long. The attacker has been inside since last night. Two things will happen on a clock, and one wrong isolation can take authentication down for the whole company.',
  start: hm(8, 0), end: hm(11, 0), dates: ['09-14', '09-15'],
  fields: FIELDS, srcdesc: SRCDESC, users: USERS, build, alerts: ALERTS, evd: EVD,
  intel: { ti: TI, whois: WHOIS, phone: PHONE, badge: {}, hr: HR, tickets: TICKET, askIt: askIT, protectedIps: { [OFFICE]: 'this is the corporate egress address. Control-room staff lose access to corporate systems.' } },
  callable: ['mel.d', 'pri.k', 'hal.j'],
  triggers: [
    {
      flag: 'exfil', at: hm(9, 30),
      contained: (g) => anyActed(g, 'isolate hist-db01', `block-ip ${ATT}`),
      penalty: 150, penaltyLabel: 'Historian data exfiltrated', okLog: 'Exfiltration path closed before 09:30',
      note: (done, happened) => (!done ? 'The shift ended before 09:30.' : happened ? 'The archive left HIST-DB01 at 09:31 for the attacker IP because neither the host nor the destination was blocked.' : 'You closed the exfiltration path before the archive left.'),
    },
    {
      flag: 'persist', at: hm(10, 15),
      contained: (g) => acted(g, 'reset-password krbtgt'),
      penalty: 120, penaltyLabel: 'Rogue Domain Admin created with the golden ticket', okLog: 'krbtgt reset before 10:15',
      note: (done, happened) => (!done ? 'The shift ended before 10:15.' : happened ? 'At 10:16 the attacker, still holding a valid golden ticket, created a new Domain Admin. Only a krbtgt reset removes a golden ticket.' : 'You reset krbtgt before the attacker could use the golden ticket again.'),
    },
  ],
  contain: CONTAIN, wrong: WRONG, checks: CHECKS, timeline,
  gaps: ['A contractor account stayed enabled for a week after the contract ended.', 'MFA by SMS can be intercepted or socially engineered.', 'Service account passwords were weak enough to crack, and the accounts used RC4.', 'svc-hist was a Domain Admin without need.', 'No alerting on replication rights used by non-domain-controllers until it was too late.', 'DNS tunnelling was not blocked at the resolver.', 'krbtgt had never been rotated, so a stolen hash gave the attacker tickets that survive every password reset.'],
  noteTail: defaultNoteTail,
  chips: ['help', 'source=winsec event=4769 detail=*RC4* | stats count by user', 'source=winsec event=4662 | stats count by user', 'source=winsec user=administrator | sort time', 'hr c.dunn'],
  cheat: `source=winsec event=4769 detail=*RC4* | stats count by user
source=winsec event=4662 | stats count by user
source=winsec user=administrator | sort time
source=dns host=JUMP-02 | stats count by qtype
source=edr proc=7z.exe | table time,host,user,parent,cmd
hr c.dunn     ticket chg-sqlfo     reset-password krbtgt     isolate jump-02     help`,
  solution: {
    cmds: ['reset-password krbtgt', 'isolate hist-db01', 'isolate jump-02', 'snapshot jump-02', 'disable-user c.dunn', 'reset-password svc-hist', 'remove-group svc-hist domain admins', `block-ip ${ATT}`, `block-domain ${C2}`, 'notify ir-lead', 'hr c.dunn', 'ask-it dc02 replication', 'ticket chg-sqlfo', 'source=edr proc=7z.exe | table time,host,user,parent,cmd'],
    verdicts: [['I1', 'incident'], ['I2', 'incident'], ['I3', 'incident'], ['I4', 'benign'], ['I5', 'benign'], ['I6', 'incident'], ['I7', 'benign'], ['I9', 'incident']],
    pins: { I1: ['e_vpn'], I2: ['e_kerb', 'e_vpn'], I3: ['e_dcsync', 'e_svc_logon'], I4: ['e_dc02'], I5: ['e_sqlfo'], I6: ['e_dns'], I7: ['e_nightly7z'], I9: ['e_stage', 'e_golden'] },
  },
}
