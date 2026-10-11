// Shift 2 (Starter): Wren Dental Group, a fictional three-clinic dental practice.
// One phished receptionist, three look-alike scares. Every name, domain and IP is
// invented; outside IPs come from documentation ranges.
import { acted, anyActed, defaultNoteTail, did, eachDay, hm, m, makeScenario, memo, mkUsers } from '../common'
import type { Alert, Containment, GameView, ShiftDef, TimelineRow, Wrong } from '../types'

const DOM = 'wrendental.example'
const OFFICE = '203.0.113.20'
const ATT = '198.51.100.140'
const PHD = 'parcelhold-uk.com'
const SUBJ = 'Parcel delivery failed - action needed'

const FIELDS: Record<string, string> = {
  mail: 'sender rcpt subj att url dir verdict',
  proxy: 'user host src method domain url bytes_out cat age action',
  entra: 'user ip geo app dev result mfa',
  edr: 'host user proc parent cmd action sig',
}
const SRCDESC: Record<string, string> = { mail: 'Mail flow / message trace', proxy: 'Web proxy', entra: 'Entra ID sign-in logs', edr: 'Endpoint detection (process events)' }

const USERS = mkUsers([
  ['rita.q', 'RECEP-PC1', 'Reception', 'a1b2c3'], ['sam.lee', 'RECEP-PC2', 'Reception', 'd4e5f6'], ['dr.patel', 'DR-LAP-02', 'Clinical', '0f9e8d'],
  ['dr.okafor', 'DR-PC-01', 'Clinical', '7c6b5a'], ['jo.marsh', 'OFFICE-PC', 'Management', '112233'], ['tina.b', 'HYG-PC1', 'Clinical', '445566'],
  ['kev.d', 'NURSE-PC1', 'Clinical', '778899'], ['amy.r', 'NURSE-PC2', 'Clinical', 'aabbcc'], ['leo.g', 'BILL-PC1', 'Billing', 'ddeeff'],
  ['ana.s', 'BILL-PC2', 'Billing', '135790'], ['mo.h', 'HYG-PC2', 'Clinical', '246801'], ['zoe.k', 'DR-PC-02', 'Clinical', '987654'],
], 10, 40)
const U = Object.fromEntries(USERS.map((u) => [u.n, u]))
const SITES: [string, string, number][] = [
  ['www.office.com', 'business', 4000], ['outlook.office365.com', 'business', 4000], ['www.nhs.uk', 'health', 9000], ['www.gdc-uk.org', 'health', 9000],
  ['www.bbc.co.uk', 'news', 9000], ['www.google.com', 'search', 9000], ['www.dentsoft.example', 'business', 3000], ['www.royalmail.com', 'logistics', 9000],
  ['www.henryschein.example', 'supplier', 5000], ['www.youtube.com', 'media', 9000], ['www.gov.uk', 'government', 9000],
]
const MAILS = ['orders@dentalsupply.example', 'accounts@labwork.example', 'noreply@dentsoft.example', 'news@gdc-uk.example', 'jo.marsh@' + DOM]
const SUBJS = ['Order confirmation 55102', 'Lab case returned', 'Monthly statement', 'Rota for next week', 'CPD course reminder', 'Invoice 7731 attached']

const build = memo(() => makeScenario(20260407, (G) => {
  const { R, pick, ri, ev } = G
  eachDay(USERS, hm(10, 30), (u, base, end, d) => {
    const skip = d === 0 && (u.n === 'rita.q' || u.n === 'sam.lee' || u.n === 'dr.patel')
    if (!skip) for (let i = 0; i < ri(1, 3); i++) ev('entra', base + ri(hm(7, 40), end), { user: u.n, ip: OFFICE, geo: 'Leeds,GB', app: pick(['Office365 Web', 'Outlook Desktop', 'Teams']), dev: u.dev, result: 'success', mfa: 'not required' })
    for (let i = 0; i < ri(16, 26); i++) {
      const s = pick(SITES)
      ev('proxy', base + ri(hm(8, 0), end), { user: u.n, host: u.host, src: u.ip, method: R() < 0.07 ? 'POST' : 'GET', domain: s[0], url: '/' + pick(['', 'home', 'api/items', 'static/app.js']), bytes_out: ri(180, 900), cat: s[1], age: s[2], action: 'allowed' })
    }
    for (let i = 0; i < ri(4, 7); i++) ev('mail', base + ri(hm(7, 30), end), { sender: pick(MAILS), rcpt: `${u.n}@${DOM}`, subj: pick(SUBJS), att: R() < 0.3 ? 'doc.pdf' : 'none', url: '-', dir: 'inbound', verdict: 'delivered' })
    for (let i = 0; i < ri(3, 5); i++) ev('edr', base + ri(hm(7, 45), end), { host: u.host, user: u.n, proc: pick(['outlook.exe', 'chrome.exe', 'dentsoft.exe', 'acrord32.exe']), parent: 'explorer.exe', cmd: 'normal launch', action: 'allowed', sig: 'signed' })
  })

  // The attack
  for (const n of ['rita.q', 'sam.lee', 'jo.marsh']) ev('mail', hm(8, 42, n.length), { sender: `delivery@${PHD}`, rcpt: `${n}@${DOM}`, subj: SUBJ, att: 'none', url: `https://${PHD}/redeliver?id=8812`, dir: 'inbound', verdict: 'delivered' }, n === 'rita.q' ? { key: 'e_mail' } : {})
  ev('proxy', hm(8, 51, 10), { user: 'rita.q', host: 'RECEP-PC1', src: U['rita.q'].ip, method: 'GET', domain: PHD, url: '/redeliver?id=8812', bytes_out: 300, cat: 'uncategorized', age: 2, action: 'allowed' }, { key: 'e_click' })
  ev('proxy', hm(8, 52, 3), { user: 'rita.q', host: 'RECEP-PC1', src: U['rita.q'].ip, method: 'POST', domain: PHD, url: '/redeliver/login', bytes_out: 620, cat: 'uncategorized', age: 2, action: 'allowed' }, { key: 'e_post', tag: 'b1raw' })
  ev('proxy', hm(8, 58, 40), { user: 'sam.lee', host: 'RECEP-PC2', src: U['sam.lee'].ip, method: 'GET', domain: PHD, url: '/redeliver?id=8812', bytes_out: 300, cat: 'uncategorized', age: 2, action: 'allowed' })
  ev('entra', hm(9, 5, 12), { user: 'rita.q', ip: ATT, geo: 'Amsterdam,NL', app: 'Office365 Web', dev: 'new-unknown', result: 'success', mfa: 'not required' }, { key: 'e_att_signin' })
  for (let i = 0; i < 38; i++) ev('mail', hm(9, 50, 5) + i * 4, { sender: `rita.q@${DOM}`, rcpt: `contact${i + 1}@${pick(['patients', 'suppliers', 'labs'])}.example`, subj: SUBJ, att: 'none', url: `https://${PHD}/redeliver?id=8812`, dir: 'outbound', verdict: 'delivered' }, { cond: 'spread', tag: i < 3 ? 'b5raw' : undefined, key: i === 0 ? 'e_spread' : undefined })

  // Decoys
  ev('entra', hm(8, 20, 30), { user: 'dr.patel', ip: '198.51.100.52', geo: 'Malaga,ES', app: 'Outlook Desktop', dev: U['dr.patel'].dev, result: 'success', mfa: 'not required' }, { key: 'e_patel_signin', tag: 'b2raw' })
  ev('edr', hm(9, 6, 14), { host: 'DR-PC-01', user: 'dr.okafor', proc: 'DentSoftUpdate_8.2.exe', parent: 'explorer.exe', cmd: '"C:\\Users\\dr.okafor\\Downloads\\DentSoftUpdate_8.2.exe" /silent', action: 'allowed', sig: 'unsigned' }, { key: 'e_updater', tag: 'b3raw' })
  ev('edr', hm(9, 6, 40), { host: 'DR-PC-01', user: 'dr.okafor', proc: 'dentsoft.exe', parent: 'DentSoftUpdate_8.2.exe', cmd: 'dentsoft.exe /migrate', action: 'allowed', sig: 'signed' })
  for (let i = 0; i < 7; i++) ev('entra', hm(9, 12) + i * 40, { user: 'sam.lee', ip: OFFICE, geo: 'Leeds,GB', app: 'Outlook Desktop', dev: U['sam.lee'].dev, result: 'failure', mfa: 'n/a' }, { tag: i < 3 ? 'b4raw' : undefined })
  ev('entra', hm(9, 17, 20), { user: 'sam.lee', ip: OFFICE, geo: 'Leeds,GB', app: 'Outlook Desktop', dev: U['sam.lee'].dev, result: 'success', mfa: 'not required' }, { key: 'e_lockout', tag: 'b4raw' })
}))

const ALERTS: Alert[] = [
  { id: 'B1', title: 'Web proxy: POST to newly registered domain', sev: 'low', src: 'Web proxy', ent: 'RECEP-PC1', at: hm(9, 0), sla: m(60), raw: 'b1raw',
    rule: 'Outbound POST to a domain registered under 14 days ago.',
    kv: [['User', 'rita.q (Reception)'], ['Domain age', '2 days'], ['Category', 'uncategorized'], ['Proxy action', 'allowed (monitor mode)']],
    best: 'incident', alt: {}, req: ['e_mail', 'e_post', 'e_att_signin'],
    why: 'Rita followed a "parcel delivery failed" link and typed her password into a fake page. The attacker then signed in as her from a Dutch hosting IP at 09:05. Low severity, real incident.',
    hints: ['Where did the link come from? Search mail for the domain.', 'Did anyone use the password afterwards? Search entra for rita.q.'] },
  { id: 'B2', title: 'Entra ID: sign-in from a new country (Spain)', sev: 'med', src: 'Entra ID', ent: 'dr.patel', at: hm(9, 5), sla: m(90), raw: 'b2raw',
    rule: 'Sign-in from a country not seen for this user in the last 30 days.',
    kv: [['User', 'dr.patel'], ['Country', 'Spain (new)'], ['Device', 'Known'], ['Result', 'Success']],
    best: 'benign', alt: { fp: 60 }, req: ['e_patel_signin', 'c_hr'],
    why: 'Dr Patel is on approved leave in Spain and asked to keep checking email. The device ID matches his normal laptop. Check the person, not just the rule. Disabling him would have been the wrong move.',
    hints: ['Compare the device ID with his sign-ins yesterday, then check HR.'] },
  { id: 'B3', title: 'EDR: unsigned executable run from Downloads', sev: 'high', src: 'EDR', ent: 'DR-PC-01', at: hm(9, 10), sla: m(45), raw: 'b3raw',
    rule: 'An unsigned program launched from a user profile folder.',
    kv: [['Host', 'DR-PC-01 (dr.okafor)'], ['File', 'DentSoftUpdate_8.2.exe'], ['Signature', 'unsigned'], ['Action', 'allowed']],
    best: 'benign', alt: { it: 60, fp: 50 }, req: ['e_updater', 'c_ticket'],
    why: 'This is the practice-software vendor update booked in ticket TKT-311, run while IT watched. The vendor ships an unsigned installer, which is worth raising with them, but it is not an attack. Isolating the machine would have stopped a dentist working.',
    hints: ['Is there a ticket for this machine today? Try: ticket tkt-311 or ask-it.'] },
  { id: 'B4', title: 'Entra ID: 7 failed sign-ins then success', sev: 'low', src: 'Entra ID', ent: 'sam.lee', at: hm(9, 20), sla: m(120), raw: 'b4raw',
    rule: 'Five or more failed sign-ins followed by a success for one user.',
    kv: [['User', 'sam.lee'], ['Source', 'Office IP 203.0.113.20'], ['Device', 'Same as usual'], ['Window', '09:12 - 09:17']],
    best: 'benign', alt: { fp: 70 }, req: ['e_lockout'],
    why: 'Same device, same office address, a few typos and then a success. Sam changed his password on Friday. A password-guessing attack would come from somewhere else.',
    hints: ['Look at where the failures came from and which device made them.'] },
  { id: 'B5', title: 'Mail: 38 outbound messages in 2.5 minutes', sev: 'high', src: 'Mail flow', ent: 'rita.q', at: hm(9, 52), sla: m(30), raw: 'b5raw', late: 'spread',
    rule: 'One mailbox sent more than 30 external messages in 5 minutes.',
    kv: [['Sender', 'rita.q'], ['Subject', SUBJ], ['Recipients', 'Patients, suppliers and labs']],
    best: 'incident', alt: {}, req: ['e_spread', 'e_att_signin'],
    why: 'The attacker used the stolen mailbox to spread the same phish to Wren patients and suppliers. Containing Rita before 09:50 would have stopped it.',
    hints: ['Who sent these: Rita, or the attacker using her account? Check the sign-in.'] },
]

const EVD: Record<string, string> = {
  e_mail: 'Phishing email delivered 08:42',
  e_post: 'Password entered on the fake page 08:52',
  e_att_signin: 'Attacker sign-in from a Dutch hosting IP 09:05',
  e_patel_signin: "Dr Patel's sign-in from his own laptop",
  e_updater: 'The unsigned updater event',
  e_lockout: 'Failures and success from the same office device',
  e_spread: 'The 38 outbound phishing emails',
  c_hr: 'Checked HR (or phoned Dr Patel) about the travel',
  c_ticket: 'Found the vendor-update ticket',
}

const TI: Record<string, string> = {
  [ATT]: 'AS64501 CloudNode BV · Amsterdam, NL · commercial hosting range\n14 abuse reports this week (phishing)\nReputation: MALICIOUS',
  [PHD]: 'Reputation: MALICIOUS · 24 of 90 engines flag it\nFake courier "redelivery" page, credential-harvest kit\nFirst seen 2 days ago',
  '198.51.100.52': 'Residential broadband · Malaga, ES · no abuse history',
  [OFFICE]: 'Wren Dental corporate egress (internal address)',
}
const WHOIS: Record<string, string> = {
  [PHD]: `Domain:      ${PHD}\nCreated:     2 days ago\nRegistrar:   privacy-protected\nTLS cert:    issued 2 days ago`,
  'dentsoft.example': 'Domain:      dentsoft.example\nCreated:     2008\nRegistrant:  DentSoft Systems Ltd (the practice-software vendor)',
}
const PHONE: Record<string, string> = {
  'rita.q': 'Rita Q.:\n"I got a parcel email, the page asked me to sign in to see the delivery so I did. It looked a bit odd afterwards. Oh no."',
  'sam.lee': 'Sam Lee:\n"I clicked the parcel link, the page was blank so I closed it. And yes, I mistyped my password a few times, I changed it Friday."',
  'dr.patel': 'Dr Patel:\n"Yes, I am in Malaga until the 13th. I said I would keep an eye on email. That is my own laptop."',
  'dr.okafor': 'Dr Okafor:\n"The vendor rang and did the update with Dan from IT sat next to me. Everything works."',
}
const HR: Record<string, string> = {
  'dr.patel': 'Dentist · APPROVED annual leave 04-06 to 04-13 (Spain) · asked to monitor email.',
  'rita.q': 'Receptionist · full-time · no leave.',
}
const TICKET: Record<string, string> = { 'tkt-311': 'TKT-311 · Approved · DentSoft 8.2 update on DR-PC-01\nWindow: 09:00 - 09:30 today · vendor remote session with IT present\nNote: vendor installer is not code-signed.' }
function askIT(q: string): string {
  if (/dentsoft|update|installer|okafor/i.test(q)) return 'IT: DentSoft is updating Dr Okafor\'s machine this morning, see ticket TKT-311.'
  if (/parcel|redeliver|royal/i.test(q)) return 'IT: we have not sent or expected any parcel notices. Treat them as spam.'
  return 'IT: not sure, can you raise a ticket?'
}

const CONTAIN: Containment[] = [
  { label: "Revoke Rita's sessions", pts: 40, t: (g) => acted(g, 'revoke-sessions rita.q') },
  { label: "Reset Rita's password", pts: 40, t: (g) => acted(g, 'reset-password rita.q') },
  { label: `Block ${PHD}`, pts: 30, t: (g) => acted(g, `block-domain ${PHD}`) },
  { label: 'Purge the phishing email from all mailboxes', pts: 40, t: (g) => acted(g, `purge-mail ${SUBJ.toLowerCase()}`) },
  { label: 'Block the attacker IP', pts: 20, t: (g) => acted(g, `block-ip ${ATT}`) },
  { label: 'Warn management so patients and suppliers are told', pts: 30, t: (g) => acted(g, 'notify management'), when: (g) => !!g.flags.spread },
]
const WRONG: Wrong[] = [
  { label: 'Disabled dr.patel (on approved leave)', pts: -50, t: (g) => acted(g, 'disable-user dr.patel') },
  { label: 'Isolated DR-PC-01 (approved vendor update)', pts: -50, t: (g) => acted(g, 'isolate dr-pc-01') },
  { label: 'Blocked the office egress IP (outage)', pts: -80, t: (g) => acted(g, `block-ip ${OFFICE}`) },
  { label: 'Disabled sam.lee (typos)', pts: -30, t: (g) => acted(g, 'disable-user sam.lee') },
]
const CHECKS: Record<string, (g: GameView) => boolean> = {
  c_hr: (g) => did(g, /^(hr|phone)\s+dr\.patel/i),
  c_ticket: (g) => did(g, /^ticket\s+tkt-311/i) || did(g, /^ask-it\s.*(dentsoft|update|okafor)/i),
}
function timeline(k: Set<string>, g: GameView): TimelineRow[] {
  const rows: TimelineRow[] = [
    { at: hm(8, 42), text: '"Parcel delivery failed" phish delivered to three staff', ttp: 'T1566.002 Spearphishing link', found: k.has('e_mail') },
    { at: hm(8, 52), text: 'Rita enters her password on a fake courier page', ttp: 'T1056.003 Credential capture', found: k.has('e_post') },
    { at: hm(9, 5), text: 'Attacker signs in as Rita from a Dutch hosting IP (no MFA required)', ttp: 'T1078.004 Valid cloud accounts', found: k.has('e_att_signin') },
  ]
  if (g.flags.spread) rows.push({ at: hm(9, 50), text: "The attacker sends the same phish to 38 patients, suppliers and labs from Rita's mailbox", ttp: 'T1534 Internal spearphishing / T1566', found: k.has('e_spread') })
  return rows
}

export const shift2: ShiftDef = {
  id: 'soc-2',
  title: 'Wren Dental: the parcel notice',
  company: 'Wren Dental Group',
  level: 'Starter',
  blurb: 'One phished receptionist and three look-alike scares. A gentle first shift: learn the console, tell a real incident from routine.',
  intro: 'You are the only analyst covering Wren Dental Group, a fictional three-clinic dental practice with 60 staff, from 09:00 to 10:30. There is no MFA yet and the proxy only watches new domains. Four alerts are waiting. Not all of them are bad.',
  start: hm(9, 0),
  end: hm(10, 30),
  dates: ['04-06', '04-07'],
  fields: FIELDS, srcdesc: SRCDESC, users: USERS, build, alerts: ALERTS, evd: EVD,
  intel: { ti: TI, whois: WHOIS, phone: PHONE, badge: {}, hr: HR, tickets: TICKET, askIt: askIT, protectedIps: { [OFFICE]: 'this is the practice egress address. All three clinics lose internet access.' } },
  callable: ['rita.q', 'sam.lee', 'dr.patel', 'dr.okafor'],
  triggers: [{
    flag: 'spread', at: hm(9, 50),
    contained: (g) => anyActed(g, 'disable-user rita.q') || acted(g, 'revoke-sessions rita.q', 'reset-password rita.q'),
    penalty: 60, penaltyLabel: 'Phish spread to patients and suppliers', okLog: "Rita's account contained before 09:50",
    note: (done, happened) => (!done ? 'The shift ended before the 09:50 deadline.' : happened ? "The attacker used Rita's mailbox to send the phish to 38 outside contacts before you contained her." : "You contained Rita's account before the attacker could use her mailbox."),
  }],
  contain: CONTAIN, wrong: WRONG, checks: CHECKS, timeline,
  gaps: ['No MFA on any account, so a stolen password was enough.', 'The proxy monitored newly registered domains instead of blocking them.', 'No limit on outbound mail volume per mailbox.', 'Staff had no quick way to report a suspicious email.'],
  noteTail: defaultNoteTail,
  chips: ['help', 'source=mail subj="Parcel*" | stats count by rcpt', 'source=entra user=rita.q | table time,ip,geo,result', `ti ${ATT}`, 'hr dr.patel'],
  cheat: `source=mail subj="Parcel*" | stats count by rcpt
source=entra user=rita.q | table time,ip,geo,result
source=proxy domain=parcelhold* | stats count by user
ti 198.51.100.140     whois some-domain.com
hr dr.patel     ticket tkt-311     revoke-sessions rita.q     help`,
  solution: {
    cmds: ['revoke-sessions rita.q', 'reset-password rita.q', `block-domain ${PHD}`, `purge-mail ${SUBJ}`, `block-ip ${ATT}`, 'source=entra user=rita.q', 'hr dr.patel', 'ticket tkt-311', 'notify management'],
    verdicts: [['B1', 'incident'], ['B2', 'benign'], ['B3', 'benign'], ['B4', 'benign']],
    pins: { B1: ['e_mail', 'e_post', 'e_att_signin'], B2: ['e_patel_signin'], B3: ['e_updater'], B4: ['e_lockout'] },
  },
}
