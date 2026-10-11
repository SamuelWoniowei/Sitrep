// Shift 7 (Hard): Orchard Health Trust, a fictional group of clinics.
// A web shell on the patient portal, credential theft, lateral movement to the
// app tier, and a database export queued for 10:50. Four alerts are routine.
import { acted, defaultNoteTail, did, eachDay, hm, m, makeScenario, memo, mkUsers } from '../common'
import type { Alert, Containment, GameView, ShiftDef, TimelineRow, Wrong } from '../types'

const ATT = '198.51.100.150'
const SCANNER = '10.60.9.5'
const CRAWL = '192.0.2.60'
const OFFICE = '203.0.113.80'
const WEB_IP = '10.60.2.15'

const FIELDS: Record<string, string> = {
  web: 'src method path status ua bytes waf',
  edr: 'host user proc parent cmd action sig',
  winsec: 'host user event src detail',
  fw: 'src dst port action bytes',
}
const SRCDESC: Record<string, string> = { web: 'Patient-portal web server access log with WAF verdict', edr: 'Endpoint detection (process events)', winsec: 'Windows Security event log (4624 logon, 4625 failed logon)', fw: 'Perimeter and DMZ firewall' }

const USERS = mkUsers([
  ['adm.rowe', 'ADM-WS-01', 'IT', 'o01'], ['dba.nair', 'ADM-WS-02', 'IT', 'o02'], ['app.owner', 'APP-WS-01', 'IT', 'o03'], ['nurse.lead', 'CLIN-WS-01', 'Clinical', 'o04'],
  ['recep.1', 'CLIN-WS-02', 'Clinical', 'o05'], ['hr.manager', 'HR-WS-01', 'HR', 'o06'], ['svc-portal', 'PORTAL-WEB01', 'Service', 'o07'], ['svc-sql', 'DB-SRV01', 'Service', 'o08'],
], 10, 90)
const PAT = ['198.51.100.21', '198.51.100.22', '203.0.113.141', '203.0.113.142', '203.0.113.143', '192.0.2.31', '192.0.2.32', '198.51.100.23', '203.0.113.144', '192.0.2.33']
const SQLI = ["/login?user=' OR 1=1--", '/records?id=1 UNION SELECT NULL', '/files?path=../../etc/passwd', '/search?q=<script>alert(1)</script>', '/admin/config.php', '/appointments?id=1;WAITFOR DELAY']

const build = memo(() => makeScenario(20260721, (G) => {
  const { R, pick, ri, ev } = G
  for (const base of [-86400, 0]) {
    const end = base < 0 ? hm(23, 0) : hm(12, 30)
    for (let i = 0; i < 260; i++) ev('web', base + ri(hm(7, 0), end), { src: pick(PAT), method: R() < 0.2 ? 'POST' : 'GET', path: pick(['/', '/login', '/appointments', '/records', '/messages', '/prescriptions', '/static/app.js']), status: R() < 0.04 ? 404 : 200, ua: pick(['Mozilla/5.0 (Windows)', 'Mozilla/5.0 (iPhone)', 'Mozilla/5.0 (Android)']), bytes: ri(400, 30000), waf: '-' })
    ev('winsec', base + hm(1, 0), { host: 'PORTAL-WEB01', user: 'svc-portal', event: '4624', src: 'localhost', detail: 'type=5 service logon' })
  }
  eachDay(USERS.filter((u) => u.dept !== 'Service'), hm(12, 30), (u, base, end) => {
    for (let i = 0; i < ri(2, 3); i++) ev('winsec', base + ri(hm(7, 30), end), { host: u.host, user: u.n, event: '4624', src: u.ip, detail: 'type=2 interactive' })
    for (let i = 0; i < ri(3, 5); i++) ev('edr', base + ri(hm(7, 30), end), { host: u.host, user: u.n, proc: pick(['outlook.exe', 'chrome.exe', 'ssms.exe', 'teams.exe']), parent: 'explorer.exe', cmd: 'normal launch', action: 'allowed', sig: 'signed' })
  })
  ev('winsec', -86400 + hm(14, 0), { host: 'PORTAL-WEB01', user: 'adm.rowe', event: '4624', src: '10.60.1.10', detail: 'type=10 RDP · monthly check' })

  // The intrusion (last night)
  ev('web', -86400 + hm(22, 40, 12), { src: ATT, method: 'POST', path: '/upload/avatar?name=help.aspx', status: 200, ua: 'python-requests/2.31', bytes: 1832, waf: 'detected (monitor mode)' }, { key: 'e_upload', tag: 'g1raw' })
  ev('web', -86400 + hm(22, 41, 3), { src: ATT, method: 'GET', path: '/uploads/help.aspx?cmd=whoami', status: 200, ua: 'python-requests/2.31', bytes: 64, waf: '-' }, { key: 'e_shell_get', tag: 'g1raw' })
  ev('edr', -86400 + hm(22, 41, 5), { host: 'PORTAL-WEB01', user: 'IIS APPPOOL\\portal', proc: 'cmd.exe', parent: 'w3wp.exe', cmd: 'cmd.exe /c whoami', action: 'allowed', sig: 'signed' }, { key: 'e_w3wp_cmd', tag: 'g2raw' })
  ev('edr', -86400 + hm(22, 42, 30), { host: 'PORTAL-WEB01', user: 'IIS APPPOOL\\portal', proc: 'cmd.exe', parent: 'w3wp.exe', cmd: 'cmd.exe /c net view /domain && ipconfig /all', action: 'allowed', sig: 'signed' }, { tag: 'g2raw' })
  ev('edr', -86400 + hm(23, 10, 40), { host: 'PORTAL-WEB01', user: 'IIS APPPOOL\\portal', proc: 'rundll32.exe', parent: 'cmd.exe', cmd: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 612 C:\\Windows\\Temp\\x.dmp full', action: 'allowed', sig: 'signed' }, { key: 'e_dump', tag: 'g2raw' })
  ev('winsec', -86400 + hm(23, 25, 18), { host: 'APP-SRV03', user: 'svc-portal', event: '4624', src: WEB_IP, detail: 'type=10 RDP · from PORTAL-WEB01' }, { key: 'e_rdp_lat', tag: 'g4raw' })
  for (let i = 0; i < 14; i++) ev('web', hm(1, 0) + i * 1500, { src: ATT, method: 'GET', path: '/uploads/help.aspx?cmd=dir', status: 200, ua: 'python-requests/2.31', bytes: 480, waf: '-' })
  // the export queued for 10:50
  ev('edr', hm(10, 52, 10), { host: 'APP-SRV03', user: 'svc-portal', proc: 'sqlcmd.exe', parent: 'cmd.exe', cmd: 'sqlcmd -S DB-SRV01 -Q "SELECT * FROM patients" -o \\\\PORTAL-WEB01\\c$\\temp\\p.csv', action: 'allowed', sig: 'signed' }, { cond: 'exfil', key: 'e_export' })
  for (let i = 0; i < 15; i++) ev('fw', hm(10, 56) + i * 60, { src: WEB_IP, dst: ATT, port: 443, action: 'allow', bytes: 150000000 + i * 1000000 }, { cond: 'exfil', tag: i < 3 ? 'g8raw' : undefined, key: i === 0 ? 'e_exfil_fw' : undefined })

  // Decoys
  for (let i = 0; i < 480; i++) ev('web', hm(9, 0) + Math.floor(i * 3.7), { src: SCANNER, method: 'GET', path: pick(SQLI), status: pick([400, 403, 404, 500]), ua: 'VulnScan/9.1', bytes: ri(200, 900), waf: 'blocked' }, i === 0 ? { key: 'e_scan', tag: 'g3raw' } : i < 3 ? { tag: 'g3raw' } : {})
  ev('edr', hm(9, 31, 5), { host: 'APP-SRV03', user: 'SYSTEM', proc: 'MsMpEng.exe', parent: 'services.exe', cmd: 'OpenProcess lsass.exe (read, scheduled scan)', action: 'allowed', sig: 'signed (Microsoft)' }, { key: 'e_defender', tag: 'g5raw' })
  ev('winsec', hm(9, 20, 44), { host: 'PORTAL-WEB01', user: 'adm.rowe', event: '4624', src: '10.60.1.10', detail: 'type=10 RDP · patch window' }, { key: 'e_patch', tag: 'g6raw' })
  ev('edr', hm(9, 24, 0), { host: 'PORTAL-WEB01', user: 'adm.rowe', proc: 'wusa.exe', parent: 'explorer.exe', cmd: 'wusa.exe windows10.0-kb5034441.msu /quiet', action: 'allowed', sig: 'signed' }, { tag: 'g6raw' })
  for (let i = 0; i < 400; i++) ev('web', hm(9, 40) + Math.floor(i * 3), { src: CRAWL, method: 'GET', path: `/page-${ri(100, 999)}`, status: 404, ua: 'SiteIndexBot/2.0', bytes: 210, waf: '-' }, i === 0 ? { key: 'e_crawl', tag: 'g7raw' } : i < 3 ? { tag: 'g7raw' } : {})
}))

const ALERTS: Alert[] = [
  { id: 'G1', title: 'WAF: executable file upload (.aspx) to /upload/avatar', sev: 'med', src: 'WAF', ent: 'PORTAL-WEB01', at: hm(10, 0), sla: m(30), raw: 'g1raw',
    rule: 'A request uploaded a file with a server-side script extension.',
    kv: [['Source', ATT], ['Path', '/upload/avatar?name=help.aspx'], ['Response', '200 OK'], ['WAF mode', 'monitor only (not blocking)'], ['Time', 'Yesterday 22:40']],
    best: 'incident', alt: {}, req: ['e_upload', 'e_shell_get'],
    why: 'The avatar upload accepted a script file and the WAF only logged it. The same IP then requested the uploaded file with a command. That is a web shell (T1505.003).',
    hints: ['After the upload, did anything request that file?', 'Search web for the attacker IP and read the paths.'] },
  { id: 'G2', title: 'EDR: w3wp.exe spawned cmd.exe on PORTAL-WEB01', sev: 'high', src: 'EDR', ent: 'PORTAL-WEB01', at: hm(10, 5), sla: m(30), raw: 'g2raw',
    rule: 'The IIS worker process started a command shell.',
    kv: [['Host', 'PORTAL-WEB01'], ['Parent', 'w3wp.exe'], ['Commands', 'whoami; net view; ipconfig; MiniDump'], ['Time', 'Yesterday 22:41 - 23:10']],
    best: 'incident', alt: {}, req: ['e_w3wp_cmd', 'e_dump'],
    why: 'Web servers do not run whoami. Commands came from the web shell. The later rundll32 comsvcs.dll MiniDump call is a credential dump of process 612 (lsass), which means svc-portal\'s password is in the attacker\'s hands.',
    hints: ['Read every command from the host, not just the first.', 'Which process did MiniDump target?'] },
  { id: 'G3', title: 'WAF: 480 SQL injection and traversal requests from 10.60.9.5', sev: 'high', src: 'WAF', ent: SCANNER, at: hm(10, 0), sla: m(60), raw: 'g3raw',
    rule: 'More than 100 requests matching injection signatures in 10 minutes.',
    kv: [['Source', `${SCANNER} (internal)`], ['User agent', 'VulnScan/9.1'], ['WAF verdict', 'blocked'], ['Window', '09:00 - 09:30']],
    best: 'benign', alt: { it: 60 }, req: ['e_scan', 'c_ticket'],
    why: 'This is the weekly authorised vulnerability scan (CHG-VS-12) from the internal scanner, and the WAF blocked everything. Loud, but expected. Do not confuse this noise with G1: the attacker used one polite upload.',
    hints: ['The source is internal. What device is 10.60.9.5? Check change tickets.'] },
  { id: 'G4', title: 'Windows: svc-portal RDP logon to APP-SRV03 from PORTAL-WEB01', sev: 'high', src: 'Windows Security', ent: 'APP-SRV03', at: hm(10, 15), sla: m(30), raw: 'g4raw',
    rule: 'A service account logged on interactively (type 10).',
    kv: [['Account', 'svc-portal'], ['Source', `PORTAL-WEB01 (${WEB_IP})`], ['Target', 'APP-SRV03'], ['Time', 'Yesterday 23:25']],
    best: 'incident', alt: {}, req: ['e_rdp_lat', 'e_dump'],
    why: 'Lateral movement (T1021.001). A web server has no reason to remote-desktop anywhere, and service accounts do not log on interactively. It came 15 minutes after the credential dump.',
    hints: ['Service accounts do not use remote desktop. When was the dump?'] },
  { id: 'G5', title: 'EDR: lsass.exe accessed by MsMpEng.exe on APP-SRV03', sev: 'high', src: 'EDR', ent: 'APP-SRV03', at: hm(10, 10), sla: m(60), raw: 'g5raw',
    rule: 'A process opened a handle to the LSASS process.',
    kv: [['Host', 'APP-SRV03'], ['Process', 'MsMpEng.exe (Microsoft Defender)'], ['Signature', 'signed (Microsoft)'], ['Parent', 'services.exe']],
    best: 'benign', alt: { fp: 60 }, req: ['e_defender', 'c_lsass'],
    why: 'Defender reads LSASS during its scheduled scan. Compare it to the real credential dump on PORTAL-WEB01 (G2): unsigned parent chain from a web process, and a MiniDump call. Same technique name, completely different meaning.',
    hints: ['Who is the process, who is its parent, and is it signed?'] },
  { id: 'G6', title: 'Windows: RDP logon to PORTAL-WEB01 by adm.rowe', sev: 'med', src: 'Windows Security', ent: 'PORTAL-WEB01', at: hm(10, 20), sla: m(60), raw: 'g6raw',
    rule: 'Interactive logon to a DMZ server outside the monthly check window.',
    kv: [['Account', 'adm.rowe (IT)'], ['Source', '10.60.1.10 (admin jump host)'], ['Time', 'Today 09:20']],
    best: 'benign', alt: { it: 60 }, req: ['e_patch', 'c_ticket300'],
    why: 'Adam Rowe patched the portal server in the approved window (CHG-300). Remember that the attacker used svc-portal, not adm.rowe. Disabling him would have been the wrong call.',
    hints: ['Is there a ticket for work on PORTAL-WEB01 this morning?'] },
  { id: 'G7', title: 'Web: 400 not-found responses from 192.0.2.60', sev: 'low', src: 'Web server', ent: CRAWL, at: hm(10, 25), sla: m(180), raw: 'g7raw',
    rule: 'More than 200 404 responses to one address in 20 minutes.',
    kv: [['Source', CRAWL], ['User agent', 'SiteIndexBot/2.0'], ['Responses', 'all 404']],
    best: 'benign', alt: { fp: 60 }, req: ['e_crawl'],
    why: 'A search-engine style crawler guessing page names. All 404s, no uploads, no POSTs.',
    hints: ['Did it ever get anything other than a 404?'] },
  { id: 'G8', title: 'Firewall: 2.3 GB outbound from PORTAL-WEB01 to a rare destination', sev: 'high', src: 'Firewall', ent: 'PORTAL-WEB01', at: hm(11, 5), sla: m(15), raw: 'g8raw', late: 'exfil',
    rule: 'More than 1 GB sent from a DMZ server to an address it has never contacted.',
    kv: [['Source', `PORTAL-WEB01 (${WEB_IP})`], ['Destination', `${ATT}:443`], ['Volume', '2.3 GB over 15 minutes']],
    best: 'incident', alt: {}, req: ['e_exfil_fw', 'e_export'],
    why: 'At 10:52 the attacker exported the patients table through APP-SRV03 and pushed it out through the web server. This is a reportable patient-data breach. Isolating PORTAL-WEB01 before 10:50 would have prevented it.',
    hints: ['The destination is the attacker IP from G1.'] },
]
const EVD: Record<string, string> = {
  e_upload: 'The .aspx upload to /upload/avatar',
  e_shell_get: 'The request that ran a command through it',
  e_w3wp_cmd: 'w3wp.exe spawning cmd.exe /c whoami',
  e_dump: 'rundll32 comsvcs.dll MiniDump of lsass (credential dump)',
  e_rdp_lat: 'svc-portal RDP logon from the web server to APP-SRV03',
  e_exfil_fw: '2.3 GB outbound to the attacker IP',
  e_export: 'sqlcmd export of the patients table',
  e_scan: 'Scanner traffic, all blocked',
  e_defender: 'Defender scheduled-scan access to lsass',
  e_patch: 'adm.rowe patching during the approved window',
  e_crawl: 'The 404-only crawler',
  c_ticket: 'Found the vulnerability-scan change ticket',
  c_lsass: 'Checked the parent and signature, or compared with PORTAL-WEB01',
  c_ticket300: 'Found the CHG-300 patch ticket',
}
const TI: Record<string, string> = {
  [ATT]: 'AS64504 OvalNet Ltd · hosting range · 112 abuse reports (web-shell operators)\nSeen uploading .aspx shells to healthcare portals this month\nReputation: MALICIOUS',
  [CRAWL]: 'Known search-indexing crawler range · clean',
  [SCANNER]: 'Orchard internal vulnerability scanner (VS-01)',
  [OFFICE]: 'Orchard Health office egress (internal address)',
}
const PHONE: Record<string, string> = {
  'adm.rowe': 'Adam Rowe (IT):\n"Yes, I patched PORTAL-WEB01 this morning, CHG-300. I did not touch svc-portal or create any files."',
  'app.owner': 'App owner:\n"The portal avatar upload only lets people send images. Nobody uses svc-portal to log on to a server, it should only run services."',
  'dba.nair': 'DBA Nair:\n"I did not run an export. Only the app tier should talk to DB-SRV01."',
}
const HR: Record<string, string> = { 'adm.rowe': 'Senior Systems Admin · patching lead.', 'svc-portal': 'Service account for the patient portal. No human owner for interactive use.' }
const TICKET: Record<string, string> = {
  'chg-vs-12': 'CHG-VS-12 · Standing · weekly authorised vulnerability scan from VS-01 (10.60.9.5), Wednesdays 09:00-10:00 against the DMZ.',
  'chg-300': 'CHG-300 · Approved · requester adm.rowe\nScope: monthly Windows patching of PORTAL-WEB01\nWindow: 09:00 - 10:00 today',
}
function askIT(q: string): string {
  if (/scan|vulnscan|10\.60\.9\.5|vs-01/i.test(q)) return 'IT: VS-01 runs the authorised weekly vulnerability scan every Wednesday morning, see CHG-VS-12.'
  if (/patch|rowe|chg-300|portal-web01/i.test(q)) return 'IT: PORTAL-WEB01 was patched this morning under CHG-300.'
  if (/defender|msmpeng|lsass/i.test(q)) return 'IT: Defender runs scheduled scans on the servers at 09:30.'
  return 'IT: not sure, can you raise a ticket?'
}
const CONTAIN: Containment[] = [
  { label: 'Isolate PORTAL-WEB01', pts: 60, t: (g) => acted(g, 'isolate portal-web01') },
  { label: 'Snapshot PORTAL-WEB01 for forensics', pts: 30, t: (g) => acted(g, 'snapshot portal-web01') },
  { label: 'Reset the svc-portal password', pts: 35, t: (g) => acted(g, 'reset-password svc-portal') },
  { label: 'Isolate APP-SRV03 (lateral movement target)', pts: 35, t: (g) => acted(g, 'isolate app-srv03') },
  { label: `Block ${ATT}`, pts: 20, t: (g) => acted(g, `block-ip ${ATT}`) },
  { label: 'Remove the web shell (after the snapshot)', pts: 20, t: (g) => [...g.actions].some((x) => x.startsWith('delete-file portal-web01')) && acted(g, 'snapshot portal-web01') },
  { label: 'Tell the incident-response lead', pts: 15, t: (g) => acted(g, 'notify ir-lead') },
  { label: 'Tell the data-protection officer', pts: 25, t: (g) => acted(g, 'notify dpo'), when: (g) => !!g.flags.exfil },
]
const WRONG: Wrong[] = [
  { label: 'Disabled adm.rowe (approved patching)', pts: -40, t: (g) => acted(g, 'disable-user adm.rowe') },
  { label: 'Blocked the internal scanner (authorised scan)', pts: -30, t: (g) => acted(g, `block-ip ${SCANNER}`) },
  { label: 'Isolated DB-SRV01 with no evidence against it (patient-system outage)', pts: -50, t: (g) => acted(g, 'isolate db-srv01') },
  { label: 'Deleted the web shell without taking a snapshot (destroys evidence)', pts: -40, t: (g) => [...g.actions].some((x) => x.startsWith('delete-file portal-web01')) && !acted(g, 'snapshot portal-web01') },
  { label: 'Blocked the office egress IP (outage)', pts: -80, t: (g) => acted(g, `block-ip ${OFFICE}`) },
]
const CHECKS: Record<string, (g: GameView) => boolean> = {
  c_ticket: (g) => did(g, /^ticket\s+chg-vs-12/i) || did(g, /^ask-it\s.*(scan|vulnscan|vs-01|10\.60\.9\.5)/i),
  c_ticket300: (g) => did(g, /^ticket\s+chg-300/i) || did(g, /^ask-it\s.*(patch|rowe|chg-300)/i) || did(g, /^phone\s+adm\.rowe/i),
  c_lsass: (g) => did(g, /lsass|MiniDump|comsvcs/i) || did(g, /source=edr.*(host=PORTAL-WEB01|parent=w3wp)/i) || did(g, /^ask-it\s.*(defender|msmpeng|lsass)/i),
}
function timeline(k: Set<string>, g: GameView): TimelineRow[] {
  const rows: TimelineRow[] = [
    { at: -86400 + hm(22, 40), text: 'Attacker uploads help.aspx through the avatar form; the WAF only logs it', ttp: 'T1190 Exploit public-facing application', found: k.has('e_upload') },
    { at: -86400 + hm(22, 41), text: 'First command through the web shell: whoami', ttp: 'T1505.003 Web shell', found: k.has('e_shell_get') || k.has('e_w3wp_cmd') },
    { at: -86400 + hm(23, 10), text: 'Credential dump of lsass with comsvcs.dll MiniDump', ttp: 'T1003.001 LSASS memory', found: k.has('e_dump') },
    { at: -86400 + hm(23, 25), text: 'svc-portal remote-desktops from the web server to APP-SRV03', ttp: 'T1021.001 Remote Desktop Protocol', found: k.has('e_rdp_lat') },
  ]
  if (g.flags.exfil) {
    rows.push({ at: hm(10, 52), text: 'sqlcmd exports the patients table via APP-SRV03', ttp: 'T1213 Data from information repositories', found: k.has('e_export') })
    rows.push({ at: hm(10, 56), text: '2.3 GB leaves PORTAL-WEB01 for the attacker IP', ttp: 'T1041 Exfiltration over C2 channel', found: k.has('e_exfil_fw') })
  }
  return rows
}
export const shift7: ShiftDef = {
  id: 'soc-7',
  title: 'Orchard Health: the avatar upload',
  company: 'Orchard Health Trust',
  level: 'Hard',
  blurb: 'A web shell on the patient portal, a credential dump and a hop to the app tier. Loud scanners and routine admin work hide the quiet attack.',
  intro: 'You are the analyst covering Orchard Health Trust, a fictional group of clinics, from 10:00 to 12:30. Eight alerts are queued. The loudest are not the dangerous ones. Patient data sits behind the portal, and something is queued for 10:50.',
  start: hm(10, 0), end: hm(12, 30), dates: ['07-20', '07-21'],
  fields: FIELDS, srcdesc: SRCDESC, users: USERS, build, alerts: ALERTS, evd: EVD,
  intel: { ti: TI, whois: {}, phone: PHONE, badge: {}, hr: HR, tickets: TICKET, askIt: askIT, protectedIps: { [OFFICE]: 'this is the office egress address. All clinics lose internet access.', [WEB_IP]: 'this is the patient portal. Patients can no longer book appointments.' } },
  callable: ['adm.rowe', 'app.owner', 'dba.nair'],
  triggers: [{
    flag: 'exfil', at: hm(10, 50),
    contained: (g) => acted(g, 'isolate portal-web01'),
    penalty: 150, penaltyLabel: 'Patient database exported', okLog: 'PORTAL-WEB01 isolated before 10:50',
    note: (done, happened) => (!done ? 'The shift ended before 10:50.' : happened ? 'The attacker exported the patients table at 10:52 and sent it out through the web server because PORTAL-WEB01 was still connected.' : 'You isolated the web server before the export could leave.'),
  }],
  contain: CONTAIN, wrong: WRONG, checks: CHECKS, timeline,
  gaps: ['The WAF ran in monitor-only mode.', 'The upload form accepted script extensions and stored them in a web-served folder.', 'The app pool could start cmd.exe and load comsvcs.dll without an EDR block.', 'A service account was allowed to log on interactively with RDP.', 'No egress filtering on the DMZ.', 'The web-shell activity overnight was not alerted for 11 hours.'],
  noteTail: defaultNoteTail,
  chips: ['help', `source=web src=${ATT} | table time,method,path,status`, 'source=edr host=PORTAL-WEB01 | sort time', 'source=winsec event=4624 detail=*type=10* | sort time', `ti ${ATT}`],
  cheat: `source=web waf!=- | stats count by src
source=edr host=PORTAL-WEB01 | sort time | table time,user,proc,parent,cmd
source=winsec event=4624 detail=*RDP*
source=fw dst=198.51.100.150 | stats count by dst
ticket chg-300     ask-it vulnerability scan     isolate portal-web01     help`,
  solution: {
    cmds: ['isolate portal-web01', 'snapshot portal-web01', 'reset-password svc-portal', 'isolate app-srv03', `block-ip ${ATT}`, 'delete-file portal-web01 /uploads/help.aspx', 'notify ir-lead', 'ticket chg-vs-12', 'ticket chg-300', 'source=edr host=PORTAL-WEB01 | sort time', 'source=edr proc=MsMpEng.exe'],
    verdicts: [['G1', 'incident'], ['G2', 'incident'], ['G3', 'benign'], ['G4', 'incident'], ['G5', 'benign'], ['G6', 'benign'], ['G7', 'benign']],
    pins: { G1: ['e_upload', 'e_shell_get'], G2: ['e_w3wp_cmd', 'e_dump'], G3: ['e_scan'], G4: ['e_rdp_lat', 'e_dump'], G5: ['e_defender'], G6: ['e_patch'], G7: ['e_crawl'] },
  },
}
