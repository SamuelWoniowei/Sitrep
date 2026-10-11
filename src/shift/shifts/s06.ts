// Shift 6 (Medium): Brightwell Cloud Labs, a fictional software start-up.
// A cloud access key leaks into a public repository and is used to mine crypto,
// create a backdoor user and then, at 14:00, to steal a customer bucket.
import { acted, defaultNoteTail, did, eachDay, hm, m, makeScenario, memo, mkUsers } from '../common'
import type { Alert, Containment, GameView, ShiftDef, TimelineRow, Wrong } from '../types'

const OFFICE = '203.0.113.70'
const CI_IP = '198.51.100.30'
const ATT = '198.51.100.115'
const PROBE = '192.0.2.140'
const LEAKED = 'AKIAEXAMPLE7KEY4XQ2'
const BACK = 'AKIAEXAMPLEBACK9Z3'

const FIELDS: Record<string, string> = {
  cloudtrail: 'actor ip region op detail',
  github: 'user repo event detail',
  billing: 'service region usd note',
  guardduty: 'finding resource detail',
}
const SRCDESC: Record<string, string> = { cloudtrail: 'Cloud audit log (API calls and console logins)', github: 'Source-control audit log', billing: 'Hourly cloud spend by service and region', guardduty: 'Cloud threat-detection findings' }

const USERS = mkUsers([
  ['maya.r', 'DEV-LAP-01', 'Engineering', 'b01'], ['ed.b', 'CEO-LAP', 'Management', 'b02'], ['sam.k', 'OPS-LAP-01', 'DevOps', 'b03'], ['li.w', 'DEV-LAP-02', 'Engineering', 'b04'],
  ['ravi.t', 'DEV-LAP-03', 'Engineering', 'b05'], ['nora.j', 'DEV-LAP-04', 'Engineering', 'b06'], ['fay.c', 'SUP-LAP-01', 'Support', 'b07'], ['otis.h', 'DEV-LAP-05', 'Engineering', 'b08'],
], 10, 80)
const DEVS = USERS.filter((u) => u.dept === 'Engineering' || u.dept === 'DevOps')

const build = memo(() => makeScenario(20260610, (G) => {
  const { pick, ri, ev } = G
  eachDay(DEVS, hm(15, 0), (u, base, end) => {
    for (let i = 0; i < ri(14, 26); i++) ev('cloudtrail', base + ri(hm(8, 30), end), { actor: u.n, ip: OFFICE, region: 'us-east-1', op: pick(['DescribeInstances', 'ListBuckets', 'GetObject', 'DescribeLogGroups', 'GetMetricData']), detail: 'ok' })
    for (let i = 0; i < ri(3, 8); i++) ev('github', base + ri(hm(8, 30), end), { user: u.n, repo: pick(['brightwell/app', 'brightwell/infra', 'brightwell/web']), event: pick(['push', 'push', 'pull_request', 'review']), detail: 'normal' })
  })
  for (const base of [-86400, 0]) {
    for (let h = 8; h < 15; h++) {
      if (base === 0 && h > 14) continue
      for (const [svc, usd] of [['EC2', 5], ['S3', 2], ['RDS', 3], ['CloudWatch', 1]] as [string, number][]) ev('billing', base + hm(h, 5), { service: svc, region: 'us-east-1', usd: usd + ri(0, 1), note: 'normal' })
    }
  }
  for (let i = 0; i < 40; i++) ev('cloudtrail', -86400 + hm(12, 30) + i * 20, { actor: 'ci-deploy', ip: CI_IP, region: 'us-east-1', op: 'GetObject', detail: 'bucket=brightwell-artifacts' })

  // The leak and the attack
  ev('github', hm(10, 50, 30), { user: 'maya.r', repo: 'brightwell/demo-tools', event: 'push', detail: `public repo · commit a91f3c adds .env containing AWS_ACCESS_KEY_ID=${LEAKED}` }, { key: 'e_leak', tag: 'f2raw' })
  ev('cloudtrail', hm(11, 2, 14), { actor: 'ops-bot', ip: ATT, region: 'us-east-2', op: 'GetCallerIdentity', detail: `key=${LEAKED}` }, { key: 'e_api_foreign', tag: 'f2raw' })
  ev('cloudtrail', hm(11, 2, 40), { actor: 'ops-bot', ip: ATT, region: 'us-east-2', op: 'ListUsers', detail: `key=${LEAKED}` })
  for (let i = 0; i < 20; i++) ev('cloudtrail', hm(11, 48) + i * 3, { actor: 'ops-bot', ip: ATT, region: 'us-east-2', op: 'RunInstances', detail: `key=${LEAKED} type=c6i.8xlarge Name=fleet-cm7731` }, i === 0 ? { key: 'e_runinstances', tag: 'f1raw' } : i < 3 ? { tag: 'f1raw' } : {})
  for (let h = 12; h <= 14; h++) ev('billing', hm(h, 5), { service: 'EC2', region: 'us-east-2', usd: 640 + h * 3, note: 'anomaly: region never used before' }, h === 12 ? { key: 'e_bill', tag: 'f1raw' } : {})
  ev('cloudtrail', hm(12, 10, 20), { actor: 'ops-bot', ip: ATT, region: 'us-east-1', op: 'CreateUser', detail: `key=${LEAKED} user=support-sync policy=AdministratorAccess` }, { key: 'e_backdoor', tag: 'f3raw' })
  ev('cloudtrail', hm(12, 10, 45), { actor: 'ops-bot', ip: ATT, region: 'us-east-1', op: 'CreateAccessKey', detail: `key=${LEAKED} user=support-sync newkey=${BACK}` }, { tag: 'f3raw' })
  ev('cloudtrail', hm(12, 15, 5), { actor: 'support-sync', ip: ATT, region: 'us-east-1', op: 'GetSecretValue', detail: `key=${BACK} secret=prod-db-password` }, { key: 'e_secret' })
  for (let i = 0; i < 30; i++) ev('cloudtrail', hm(14, 2) + i * 8, { actor: 'support-sync', ip: ATT, region: 'us-east-1', op: 'GetObject', detail: `key=${BACK} bucket=brightwell-customer-exports size=1.3GB` }, { cond: 'exfil', tag: i < 3 ? 'f7raw' : undefined, key: i === 0 ? 'e_exfil' : undefined })

  // Decoys
  for (let i = 0; i < 40; i++) ev('cloudtrail', hm(12, 30) + i * 20, { actor: 'ci-deploy', ip: CI_IP, region: 'us-east-1', op: 'GetObject', detail: 'bucket=brightwell-artifacts' }, i === 0 ? { key: 'e_ci', tag: 'f4raw' } : i < 3 ? { tag: 'f4raw' } : {})
  ev('cloudtrail', hm(13, 2, 10), { actor: 'root', ip: OFFICE, region: 'us-east-1', op: 'ConsoleLogin', detail: 'MFA=true' }, { key: 'e_root', tag: 'f5raw' })
  ev('cloudtrail', hm(13, 6, 30), { actor: 'root', ip: OFFICE, region: 'us-east-1', op: 'UpdatePaymentMethod', detail: 'billing contact update' }, { tag: 'f5raw' })
  ev('guardduty', hm(12, 55), { finding: 'Recon:EC2/Portscan', resource: 'web-1', detail: `inbound probe from ${PROBE} blocked by security group, no connection established` }, { key: 'e_probe', tag: 'f6raw' })
}))

const ALERTS: Alert[] = [
  { id: 'F1', title: 'Billing anomaly: EC2 spend 100x normal in a new region', sev: 'high', src: 'Billing', ent: 'us-east-2', at: hm(13, 0), sla: m(30), raw: 'f1raw',
    rule: 'Hourly spend more than 10x the 7-day average, or any spend in a region never used before.',
    kv: [['Service', 'EC2'], ['Region', 'us-east-2 (never used)'], ['Spend', '$640+ per hour vs $5 normal'], ['Instances', '20 x c6i.8xlarge']],
    best: 'incident', alt: {}, req: ['e_bill', 'e_runinstances'],
    why: 'Twenty large instances started in a region the company never uses, by the ops-bot key, from an unfamiliar IP: cryptojacking. Every hour costs real money.',
    hints: ['Who launched the instances and from where? Search cloudtrail for RunInstances.'] },
  { id: 'F2', title: 'Source control: cloud access key found in a public repository', sev: 'high', src: 'GitHub', ent: 'maya.r', at: hm(13, 0), sla: m(30), raw: 'f2raw',
    rule: 'A secret scanner matched a cloud access-key pattern in a public commit.',
    kv: [['Repo', 'brightwell/demo-tools (public)'], ['Commit', 'a91f3c by maya.r'], ['Key', LEAKED], ['Found', '13:00 (pushed 10:50)']],
    best: 'incident', alt: {}, req: ['e_leak', 'e_api_foreign'],
    why: 'Maya committed a .env file to a public repo at 10:50. Automated bots found it and used it twelve minutes later. A leaked key must be treated as used until you prove otherwise.',
    hints: ['Search cloudtrail for the key ID. Was it used from anywhere other than the office or CI?'] },
  { id: 'F3', title: 'Cloud audit: new admin user and access key created', sev: 'med', src: 'CloudTrail', ent: 'support-sync', at: hm(13, 10), sla: m(45), raw: 'f3raw',
    rule: 'CreateUser with AdministratorAccess, or CreateAccessKey for a new user.',
    kv: [['Created by', 'ops-bot (the leaked key)'], ['New user', 'support-sync'], ['Policy', 'AdministratorAccess'], ['New key', BACK]],
    best: 'incident', alt: {}, req: ['e_backdoor', 'e_secret'],
    why: 'Persistence: revoking the leaked key alone would not evict the attacker, who created a new admin user and key and read the production database password. Both must go, and the secret must be rotated.',
    hints: ['Who created it? Then check what the new user did next.'] },
  { id: 'F4', title: 'Cloud audit: 40 bulk S3 reads by ci-deploy', sev: 'med', src: 'CloudTrail', ent: 'ci-deploy', at: hm(13, 15), sla: m(120), raw: 'f4raw',
    rule: 'A role read more than 30 objects in 15 minutes.',
    kv: [['Principal', 'ci-deploy'], ['Source', CI_IP], ['Bucket', 'brightwell-artifacts']],
    best: 'benign', alt: { fp: 60 }, req: ['e_ci', 'c_ci'],
    why: 'The deploy pipeline pulls build artifacts at 12:30 every day from the same runner. Compare with yesterday. Disabling its key would have broken the release pipeline.',
    hints: ['Search for the same principal yesterday at the same time.'] },
  { id: 'F5', title: 'Cloud audit: root account console login', sev: 'high', src: 'CloudTrail', ent: 'root', at: hm(13, 20), sla: m(45), raw: 'f5raw',
    rule: 'Any use of the root account.',
    kv: [['Principal', 'root'], ['Source', `${OFFICE} (office)`], ['MFA', 'true'], ['Action', 'UpdatePaymentMethod']],
    best: 'benign', alt: { it: 50 }, req: ['e_root', 'c_root'],
    why: 'Ed, the founder, logged in from the office with MFA to change the billing card. Root use is rare and worth a question, but this one is expected and low risk. Locking root would have blocked billing.',
    hints: ['Where did the login come from, and did MFA pass? Ask the person.'] },
  { id: 'F6', title: 'Threat detection: port scan against web-1', sev: 'low', src: 'GuardDuty', ent: 'web-1', at: hm(13, 30), sla: m(180), raw: 'f6raw',
    rule: 'An external address probed many ports on a server.',
    kv: [['Source', PROBE], ['Outcome', 'blocked by security group']],
    best: 'benign', alt: { fp: 60 }, req: ['e_probe'],
    why: 'Background internet scanning, blocked at the security group. No connection was established.',
    hints: ['Read the finding detail. Did anything get through?'] },
  { id: 'F7', title: 'Cloud audit: 39 GB downloaded from customer-exports bucket', sev: 'high', src: 'CloudTrail', ent: 'support-sync', at: hm(14, 5), sla: m(15), raw: 'f7raw', late: 'exfil',
    rule: 'More than 10 GB read from a bucket tagged as customer data.',
    kv: [['Principal', 'support-sync'], ['Source', ATT], ['Bucket', 'brightwell-customer-exports']],
    best: 'incident', alt: {}, req: ['e_exfil', 'e_backdoor'],
    why: 'At 14:02 the attacker used the backdoor admin key to download the customer exports bucket. This is now a reportable personal-data breach. Disabling the backdoor key before 14:00 would have prevented it.',
    hints: ['This is the backdoor user from F3.'] },
]
const EVD: Record<string, string> = {
  e_bill: 'Spend anomaly in us-east-2',
  e_runinstances: '20 RunInstances by ops-bot from the attacker IP',
  e_leak: '.env with the access key pushed to a public repo 10:50',
  e_api_foreign: 'First use of the key from the attacker IP at 11:02',
  e_backdoor: 'support-sync admin user and key created',
  e_secret: 'prod-db-password read by support-sync',
  e_exfil: '39 GB of customer exports downloaded',
  e_ci: 'ci-deploy runs the same reads daily from the runner IP',
  e_root: 'Root login from the office with MFA',
  e_probe: 'The probe was blocked by the security group',
  c_ci: 'Compared ci-deploy with yesterday or asked',
  c_root: 'Asked Ed or IT about the root login',
}
const TI: Record<string, string> = {
  [ATT]: 'AS64503 NightHost OOD · Sofia, BG · hosting range\nLinked to cloud-key cryptomining campaigns (c6i/c7i fleets)\nReputation: MALICIOUS',
  [PROBE]: 'Range seen in ~1,900 abuse reports per day · generic scanner',
  [CI_IP]: 'CI provider runner pool · Brightwell\'s hosted pipeline · clean',
  [OFFICE]: 'Brightwell office egress (internal address)',
  [LEAKED.toLowerCase()]: 'Key belongs to IAM user ops-bot · created 214 days ago, never rotated · attached policy: broad EC2/IAM/S3 access',
  [BACK.toLowerCase()]: 'Key belongs to IAM user support-sync · created 12:10 today · AdministratorAccess',
}
const PHONE: Record<string, string> = {
  'maya.r': 'Maya R.:\n"Oh no. I copied the demo folder into a public repo to show a customer and I did not notice the .env. Is that the key for ops-bot?"',
  'ed.b': 'Ed B. (founder):\n"Yes, that was me, I changed the card on the account because it expired. It was from my desk and I used my phone for MFA."',
  'sam.k': 'Sam K. (DevOps):\n"ops-bot is the old scripting user. It should have been rotated ages ago. ci-deploy runs from the CI runner every day at 12:30."',
}
const HR: Record<string, string> = { 'maya.r': 'Software Engineer · 18 months · no concerns.', 'ed.b': 'Founder and CEO.' }
function askIT(q: string): string {
  if (/ci|deploy|artifact|runner/i.test(q)) return 'DevOps: ci-deploy pulls build artifacts from the CI runner pool every day at 12:30.'
  if (/root|billing|card|payment/i.test(q)) return 'DevOps: the account card expired this week. Ed said he would update it himself.'
  if (/ops-bot|key|rotate/i.test(q)) return 'DevOps: ops-bot is the old scripting user. We keep meaning to rotate it.'
  return 'DevOps: not sure, can you raise a ticket?'
}
const CONTAIN: Containment[] = [
  { label: 'Deactivate the leaked ops-bot key', pts: 50, t: (g) => acted(g, `disable-key ${LEAKED.toLowerCase()}`) },
  { label: 'Delete the backdoor support-sync user', pts: 50, t: (g) => acted(g, 'delete-account support-sync') || acted(g, `disable-key ${BACK.toLowerCase()}`) },
  { label: 'Terminate the mining fleet (cm7731)', pts: 40, t: (g) => [...g.actions].some((x) => x.startsWith('terminate ') && x.includes('cm7731')) },
  { label: 'Rotate the prod database password', pts: 30, t: (g) => [...g.actions].some((x) => x.startsWith('rotate-secret ') && x.includes('prod-db-password')) },
  { label: `Block ${ATT}`, pts: 15, t: (g) => acted(g, `block-ip ${ATT}`) },
  { label: 'Tell the data-protection officer', pts: 25, t: (g) => acted(g, 'notify dpo'), when: (g) => !!g.flags.exfil },
]
const WRONG: Wrong[] = [
  { label: 'Disabled the ci-deploy key (breaks releases)', pts: -60, t: (g) => [...g.actions].some((x) => x.startsWith('disable-key ') && /ci/.test(x)) },
  { label: 'Locked the root account (founder is changing billing)', pts: -40, t: (g) => acted(g, 'lock root') || acted(g, 'disable-user root') },
  { label: 'Terminated production instances', pts: -80, t: (g) => [...g.actions].some((x) => x.startsWith('terminate ') && /(web|prod|db)/.test(x) && !x.includes('cm7731')) },
  { label: 'Blocked the office egress IP (outage)', pts: -80, t: (g) => acted(g, `block-ip ${OFFICE}`) },
]
const CHECKS: Record<string, (g: GameView) => boolean> = {
  c_ci: (g) => did(g, /^(phone sam\.k|ask-it\s.*(ci|deploy|artifact|runner))/i) || did(g, /source=cloudtrail.*ci-deploy/i) && did(g, /(stats|top|dedup)/i),
  c_root: (g) => did(g, /^phone\s+ed\.b/i) || did(g, /^ask-it\s.*(root|billing|card|payment)/i),
}
function timeline(k: Set<string>, g: GameView): TimelineRow[] {
  const rows: TimelineRow[] = [
    { at: hm(10, 50), text: 'Maya pushes a .env with a live cloud key to a public repository', ttp: 'T1552.001 Credentials in files', found: k.has('e_leak') },
    { at: hm(11, 2), text: 'Automated bots use the key from a Bulgarian hosting IP', ttp: 'T1078.004 Valid cloud accounts', found: k.has('e_api_foreign') },
    { at: hm(11, 48), text: '20 large instances start in us-east-2 (cryptomining)', ttp: 'T1496 Resource hijacking', found: k.has('e_runinstances') || k.has('e_bill') },
    { at: hm(12, 10), text: 'The attacker creates an admin user "support-sync" and a second key', ttp: 'T1136.003 Create cloud account', found: k.has('e_backdoor') },
    { at: hm(12, 15), text: 'support-sync reads the production database password', ttp: 'T1555 Credentials from password stores', found: k.has('e_secret') },
  ]
  if (g.flags.exfil) rows.push({ at: hm(14, 2), text: 'support-sync downloads the customer exports bucket (39 GB)', ttp: 'T1530 Data from cloud storage', found: k.has('e_exfil') })
  return rows
}
export const shift6: ShiftDef = {
  id: 'soc-6',
  title: 'Brightwell Cloud Labs: the .env file',
  company: 'Brightwell Cloud Labs',
  level: 'Medium',
  blurb: 'A cloud key leaks into a public repository. Cryptomining, a backdoor admin user and a customer-data bucket you have until 14:00 to protect.',
  intro: 'You are the on-call analyst for Brightwell Cloud Labs, a fictional 40-person software company, from 13:00 to 15:00. The cloud audit log is your main source. Remember that disabling one key does not evict an attacker who has already made another.',
  start: hm(13, 0), end: hm(15, 0), dates: ['06-09', '06-10'],
  fields: FIELDS, srcdesc: SRCDESC, users: USERS, build, alerts: ALERTS, evd: EVD,
  intel: { ti: TI, whois: {}, phone: PHONE, badge: {}, hr: HR, tickets: {}, askIt: askIT, protectedIps: { [OFFICE]: 'this is the office egress address. Developers cannot reach the console.' } },
  callable: ['maya.r', 'ed.b', 'sam.k'],
  triggers: [{
    flag: 'exfil', at: hm(14, 0),
    contained: (g) => acted(g, `disable-key ${BACK.toLowerCase()}`) || acted(g, 'delete-account support-sync'),
    penalty: 150, penaltyLabel: 'Customer data bucket downloaded', okLog: 'Backdoor user removed before 14:00',
    note: (done, happened) => (!done ? 'The shift ended before 14:00.' : happened ? 'At 14:02 the attacker used the backdoor key to download the customer exports bucket. Revoking only the leaked key was not enough.' : 'You removed the backdoor before the attacker could take the customer data.'),
  }],
  contain: CONTAIN, wrong: WRONG, checks: CHECKS, timeline,
  gaps: ['A long-lived access key was never rotated.', 'Developers could make a repository public without review.', 'No secret scanning on push; only found after 2 hours.', 'No budget alarm or service-control policy blocking unused regions.', 'The leaked key could create IAM users.'],
  noteTail: defaultNoteTail,
  chips: ['help', `source=cloudtrail detail=*${LEAKED}* | table time,ip,region,op`, `source=cloudtrail ip=${ATT} | stats count by op`, 'source=billing region=us-east-2', `ti ${ATT}`],
  cheat: `source=cloudtrail detail=*AKIAEXAMPLE7KEY4XQ2* | stats count by op
source=cloudtrail ip=198.51.100.115 | stats count by actor
source=billing region=us-east-2
ti 198.51.100.115     ti akiaexample7key4xq2
disable-key <key id>     delete-account <user>     rotate-secret <name>     terminate <tag>     help`,
  solution: {
    cmds: [`disable-key ${LEAKED}`, 'delete-account support-sync', `disable-key ${BACK}`, 'terminate fleet-cm7731', 'rotate-secret prod-db-password', `block-ip ${ATT}`, 'phone ed.b', 'ask-it ci deploy runner'],
    verdicts: [['F1', 'incident'], ['F2', 'incident'], ['F3', 'incident'], ['F4', 'benign'], ['F5', 'benign'], ['F6', 'benign']],
    pins: { F1: ['e_bill', 'e_runinstances'], F2: ['e_leak', 'e_api_foreign'], F3: ['e_backdoor', 'e_secret'], F4: ['e_ci'], F5: ['e_root'], F6: ['e_probe'] },
  },
}
