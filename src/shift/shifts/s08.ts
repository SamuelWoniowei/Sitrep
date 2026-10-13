// Shift 8 (Hard): Fenwick Pay, a fictional payments start-up.
// A poisoned dependency steals CI secrets, a forged release is tagged, and a
// production deploy is queued for 11:40. Four alerts look scary and are not.
import { acted, defaultNoteTail, did, eachDay, hm, m, makeScenario, memo, mkUsers } from '../common'
import type { Alert, Containment, GameView, ShiftDef, TimelineRow, Wrong } from '../types'

const RUNNER = '198.51.100.40'
const ATT = '198.51.100.171'
const C2 = 'telemetry-npm-cdn.com'

const FIELDS: Record<string, string> = {
  registry: 'pkg version event publisher detail',
  ci: 'repo job step event detail',
  git: 'user repo event ref ip detail',
  edr: 'host user proc parent cmd action sig',
  proxy: 'user host src method domain url bytes_out cat age action',
}
const SRCDESC: Record<string, string> = { registry: 'Package registry and advisory feed', ci: 'CI/CD pipeline job log', git: 'Source-control audit log', edr: 'Endpoint detection (process events)', proxy: 'Web and runner egress proxy' }

const USERS = mkUsers([
  ['li.w', 'DEV-LAP-01', 'Engineering', 'p01'], ['ravi.t', 'DEV-LAP-04', 'Engineering', 'p02'], ['kat.o', 'DEV-LAP-02', 'Engineering', 'p03'], ['joe.m', 'DEV-LAP-03', 'Engineering', 'p04'],
  ['dee.s', 'DEV-LAP-05', 'Engineering', 'p05'], ['bo.f', 'SEC-LAP-01', 'Security', 'p06'], ['ana.v', 'PLAT-LAP-01', 'Platform', 'p07'], ['ci-bot', 'runner-2', 'Service', 'p08'],
], 10, 100)

const build = memo(() => makeScenario(20260805, (G) => {
  const { R, pick, ri, ev } = G
  eachDay(USERS.filter((u) => u.dept !== 'Service'), hm(13, 0), (u, base, end) => {
    for (let i = 0; i < ri(5, 9); i++) ev('git', base + ri(hm(8, 30), end), { user: u.n, repo: pick(['fenwick/payments-api', 'fenwick/web', 'fenwick/docs', 'fenwick/mobile']), event: pick(['push', 'push', 'pull_request', 'review']), ref: pick(['feature/a', 'feature/b', 'main']), ip: '203.0.113.90', detail: 'normal' })
    for (let i = 0; i < ri(18, 28); i++) { const d = pick(['github.com', 'registry.npmjs.example', 'www.google.com', 'stackoverflow.com', 'docs.fenwick.example']); ev('proxy', base + ri(hm(8, 30), end), { user: u.n, host: u.host, src: u.ip, method: 'GET', domain: d, url: '/', bytes_out: ri(180, 900), cat: 'tech', age: 6000, action: 'allowed' }) }
    for (let i = 0; i < ri(3, 5); i++) ev('edr', base + ri(hm(8, 30), end), { host: u.host, user: u.n, proc: pick(['code.exe', 'node.exe', 'chrome.exe', 'docker.exe']), parent: 'explorer.exe', cmd: 'normal launch', action: 'allowed', sig: 'signed' })
  })
  for (const base of [-86400, 0]) {
    for (let i = 0; i < 9; i++) {
      const t = base + hm(8, 30) + i * 1500
      if (base === 0 && t > hm(11, 0)) continue
      ev('ci', t, { repo: 'fenwick/payments-api', job: `build #${8830 + i + (base ? 9 : 0)}`, step: 'npm ci', event: 'finish', detail: 'ok · egress only to registry.npmjs.example' })
    }
    ev('git', base + hm(9, 10), { user: 'ci-bot', repo: 'fenwick/payments-api', event: 'push', ref: 'release/3.7', ip: RUNNER, detail: 'automated version bump' })
  }

  // The poisoned package and the build that pulled it
  ev('registry', hm(6, 10, 20), { pkg: 'fenwick-utils-core', version: '2.4.1', event: 'published', publisher: 'm.volkov (added as maintainer 2 days ago)', detail: 'new postinstall script; package size +38 KB' }, { key: 'e_pkg', tag: 'h2raw' })
  ev('registry', hm(6, 11), { pkg: 'fenwick-utils-core', version: '2.4.0', event: 'published (previous)', publisher: 'fenwick-platform', detail: 'normal release 3 months ago' })
  ev('ci', hm(9, 41, 50), { repo: 'fenwick/payments-api', job: 'build #8841', step: 'npm ci', event: 'postinstall', detail: 'node_modules/fenwick-utils-core/postinstall.js executed; reads process.env (CI_BOT_TOKEN, SIGN_KEY_PASS, DEPLOY_ROLE)' }, { key: 'e_postinstall', tag: 'h1raw' })
  ev('ci', hm(9, 42, 12), { repo: 'fenwick/payments-api', job: 'build #8841', step: 'npm ci', event: 'net', detail: `unapproved egress: POST ${C2}/c 18 KB (policy: registry only)` }, { key: 'e_egress', tag: 'h1raw' })
  ev('proxy', hm(9, 42, 12), { user: 'ci-bot', host: 'runner-2', src: '10.70.3.12', method: 'POST', domain: C2, url: '/c', bytes_out: 18400, cat: 'uncategorized', age: 4, action: 'allowed' }, { tag: 'h1raw' })
  ev('git', hm(10, 5, 14), { user: 'ci-bot', repo: 'fenwick/payments-api', event: 'push', ref: 'release/3.8', ip: ATT, detail: 'commit 7c4e1a "bump deps" changes build/deploy.sh (adds curl to remote script)' }, { key: 'e_push', tag: 'h3raw' })
  ev('git', hm(10, 8, 2), { user: 'ci-bot', repo: 'fenwick/payments-api', event: 'tag', ref: 'v3.8.2', ip: ATT, detail: 'tag v3.8.2 on 7c4e1a; signed with the release key' }, { key: 'e_release', tag: 'h3raw' })
  ev('ci', hm(11, 41, 10), { repo: 'fenwick/payments-api', job: 'deploy-prod', step: 'deploy', event: 'start', detail: 'tag v3.8.2 triggered production deploy; build/deploy.sh fetched remote script' }, { cond: 'release', key: 'e_deploy', tag: 'h8raw' })
  ev('ci', hm(11, 43, 0), { repo: 'fenwick/payments-api', job: 'deploy-prod', step: 'deploy', event: 'finish', detail: 'deployed to 12 production hosts' }, { cond: 'release', tag: 'h8raw' })

  // Decoys
  ev('edr', hm(9, 15, 30), { host: 'DEV-LAP-04', user: 'ravi.t', proc: 'bash', parent: 'wsl.exe', cmd: 'bash -c "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash"', action: 'allowed', sig: 'signed' }, { key: 'e_nvm', tag: 'h4raw' })
  ev('git', hm(9, 50, 20), { user: 'kat.o', repo: 'fenwick/docs', event: 'force-push', ref: 'main', ip: '203.0.113.90', detail: 'history rewritten to remove an accidentally committed customer CSV · ticket CHG-FP-4' }, { key: 'e_force', tag: 'h5raw' })
  for (let i = 0; i < 14; i++) ev('ci', hm(9, 0) + i * 240, { repo: pick(['fenwick/web', 'fenwick/mobile', 'fenwick/docs']), job: `build #${9000 + i}`, step: 'checkout', event: 'fail', detail: 'runner-3: no space left on device' }, i === 0 ? { key: 'e_ci_fail', tag: 'h6raw' } : i < 3 ? { tag: 'h6raw' } : {})
  ev('registry', hm(8, 0, 5), { pkg: 'lodash', version: '4.17.15', event: 'advisory', publisher: '-', detail: 'prototype pollution (known CVE, fix in 4.17.21) · used by 3 Fenwick repos' }, { key: 'e_advisory', tag: 'h7raw' })
  void R
}))

const ALERTS: Alert[] = [
  { id: 'H1', title: 'CI: build job made an unapproved outbound connection', sev: 'med', src: 'CI/CD', ent: 'build #8841', at: hm(10, 30), sla: m(30), raw: 'h1raw',
    rule: 'A build step sent traffic to a host that is not the package registry.',
    kv: [['Repo', 'fenwick/payments-api'], ['Step', 'npm ci'], ['Destination', C2], ['Size', '18 KB POST']],
    best: 'incident', alt: {}, req: ['e_postinstall', 'e_egress'],
    why: 'A postinstall script from a dependency read the CI environment (the bot token, signing-key passphrase and deploy role) and posted it to an external domain. That is the theft of secrets.',
    hints: ['Which package ran a script during npm ci?', 'What environment variables did it read?'] },
  { id: 'H2', title: 'Registry: dependency published by a new maintainer', sev: 'low', src: 'Registry', ent: 'fenwick-utils-core', at: hm(10, 30), sla: m(60), raw: 'h2raw',
    rule: 'A package we depend on changed its publisher or added an install script.',
    kv: [['Package', 'fenwick-utils-core 2.4.0 -> 2.4.1'], ['Publisher', 'm.volkov (added 2 days ago)'], ['Change', 'new postinstall script, +38 KB']],
    best: 'incident', alt: {}, req: ['e_pkg', 'e_postinstall'],
    why: 'A trusted internal-looking package gained a stranger as maintainer and a script that runs on install: dependency hijack (T1195.001). The question to ask is whether any of our builds installed 2.4.1. They did, in build #8841.',
    hints: ['Did a build pull the new version? Search ci for postinstall.'] },
  { id: 'H3', title: 'Git: ci-bot pushed and tagged a release from a new IP', sev: 'high', src: 'Source control', ent: 'ci-bot', at: hm(10, 40), sla: m(30), raw: 'h3raw',
    rule: 'A service token was used from an address that is not a known runner.',
    kv: [['Token', 'ci-bot'], ['Source', ATT], ['Known runner', RUNNER], ['Action', 'push release/3.8, tag v3.8.2']],
    best: 'incident', alt: {}, req: ['e_push', 'e_release'],
    why: 'The stolen bot token was used from the attacker IP 25 minutes after the theft to push a change to build/deploy.sh and tag a signed release. The tag will trigger a production deploy.',
    hints: ['ci-bot always pushes from the runner. Compare with its history.', 'What does the commit change?'] },
  { id: 'H4', title: 'EDR: curl piped to bash on a developer laptop', sev: 'high', src: 'EDR', ent: 'DEV-LAP-04', at: hm(10, 35), sla: m(60), raw: 'h4raw',
    rule: 'curl or wget output piped straight into a shell.',
    kv: [['Host', 'DEV-LAP-04 (ravi.t)'], ['URL', 'raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh'], ['Parent', 'wsl.exe']],
    best: 'benign', alt: { it: 60, fp: 50 }, req: ['e_nvm', 'c_ask'],
    why: 'That is the documented installer for the Node Version Manager, pinned to a version tag, run in WSL. Risky habit, not an attack. Isolating a developer laptop would have stopped a day of work.',
    hints: ['What is the URL? Is it a well-known project, pinned to a tag?'] },
  { id: 'H5', title: 'Git: force-push to main on fenwick/docs', sev: 'med', src: 'Source control', ent: 'kat.o', at: hm(10, 45), sla: m(90), raw: 'h5raw',
    rule: 'Any force-push to a protected branch.',
    kv: [['User', 'kat.o'], ['Repo', 'fenwick/docs'], ['Branch', 'main'], ['Source', 'office IP']],
    best: 'benign', alt: { it: 60 }, req: ['e_force', 'c_ticket'],
    why: 'Kat rewrote history to remove a customer CSV that was committed by mistake. That was approved in CHG-FP-4. Different from H3: it is a person, from the office, with a reason.',
    hints: ['Read the detail line. Is there a ticket?'] },
  { id: 'H6', title: 'CI: 14 build failures in 1 hour', sev: 'low', src: 'CI/CD', ent: 'runner-3', at: hm(10, 50), sla: m(180), raw: 'h6raw',
    rule: 'More than 10 failed jobs on one runner within an hour.',
    kv: [['Runner', 'runner-3'], ['Cause', 'no space left on device'], ['Repos', 'web, mobile, docs']],
    best: 'it', alt: { benign: 50 }, req: ['e_ci_fail', 'c_ask'],
    why: 'A full disk on a build runner. Annoying but unrelated to H1 (a different runner). Hand it to platform.',
    hints: ['Read the failure detail. Which runner?'] },
  { id: 'H7', title: 'Registry: known vulnerable lodash in 3 repositories', sev: 'low', src: 'Registry', ent: 'lodash 4.17.15', at: hm(10, 55), sla: m(240), raw: 'h7raw',
    rule: 'A dependency matches a published advisory.',
    kv: [['Package', 'lodash 4.17.15'], ['Issue', 'prototype pollution'], ['Repos', '3']],
    best: 'it', alt: { benign: 60 }, req: ['e_advisory'],
    why: 'Ordinary vulnerability management. Raise a ticket for the owning teams. Do not confuse an old, well-known CVE with a hijacked package.',
    hints: ['A published CVE with a fix. Who owns upgrading dependencies?'] },
  { id: 'H8', title: 'CI: production deploy of v3.8.2 started', sev: 'high', src: 'CI/CD', ent: 'deploy-prod', at: hm(11, 45), sla: m(15), raw: 'h8raw', late: 'release',
    rule: 'A tag triggered a production deployment.',
    kv: [['Tag', 'v3.8.2 (ci-bot, ATT IP)'], ['Hosts', '12 production hosts'], ['Script', 'fetched a remote script']],
    best: 'incident', alt: {}, req: ['e_deploy', 'e_release'],
    why: 'The forged release deployed a modified deploy script to production payment hosts. Rotating the bot token and locking the tag before 11:40 would have stopped it.',
    hints: ['This is the tag from H3.'] },
]
const EVD: Record<string, string> = {
  e_pkg: 'fenwick-utils-core 2.4.1 published by a new maintainer',
  e_postinstall: 'postinstall.js reading CI secrets in build #8841',
  e_egress: 'POST of 18 KB to telemetry-npm-cdn.com',
  e_push: 'ci-bot pushing from the attacker IP, not the runner',
  e_release: 'Tag v3.8.2 created and signed from the attacker IP',
  e_deploy: 'Production deploy of v3.8.2',
  e_nvm: 'The nvm installer pinned to v0.39.7',
  e_force: 'The documented, ticketed history rewrite',
  e_ci_fail: 'runner-3 failures: no space left on device',
  e_advisory: 'The lodash advisory',
  c_ask: 'Asked IT, the developer or platform about it',
  c_ticket: 'Found the history-rewrite ticket',
}
const TI: Record<string, string> = {
  [C2]: 'Reputation: MALICIOUS · registered 5 days ago\nLooks like an npm telemetry host; used by 3 other poisoned packages this month',
  [ATT]: 'AS64505 StackRoute SRL · hosting range · 31 abuse reports (token abuse)\nReputation: MALICIOUS',
  [RUNNER]: 'Fenwick CI runner pool egress (internal address)',
  'raw.githubusercontent.com': 'Reputation: CLEAN · the main GitHub raw-file host',
}
const WHOIS: Record<string, string> = { [C2]: `Domain:      ${C2}\nCreated:     5 days ago\nRegistrar:   privacy-protected\nNameserver:  cloudflare` }
const PHONE: Record<string, string> = {
  'ravi.t': 'Ravi T.:\n"That is just installing nvm in WSL for the node 20 upgrade. It is the one from their README."',
  'kat.o': 'Kat O.:\n"Yes, I force-pushed docs main to remove a CSV with customer names I committed by mistake. CHG-FP-4."',
  'li.w': 'Li W.:\n"I merged the dependabot PR for fenwick-utils-core this morning. Did that break something?"',
  'ana.v': 'Ana V. (Platform):\n"runner-3 disk filled up. ci-bot should only ever push from runner-2 or runner-4. I am not aware of any new IP."',
}
const HR: Record<string, string> = {}
const TICKET: Record<string, string> = { 'chg-fp-4': 'CHG-FP-4 · Approved · requester kat.o\nScope: rewrite history of fenwick/docs main to remove commit containing a customer CSV\nApprover: bo.f (Security)' }
function askIT(q: string): string {
  if (/nvm|node|wsl|ravi/i.test(q)) return 'Platform: nvm in WSL is on our allowed developer tooling list.'
  if (/runner-3|disk|space|ci fail/i.test(q)) return 'Platform: runner-3 has been low on disk since last week. We are expanding it.'
  if (/force|docs|csv|kat/i.test(q)) return 'Platform: Kat raised CHG-FP-4 for a history rewrite on docs.'
  return 'Platform: not sure, can you raise a ticket?'
}
const CONTAIN: Containment[] = [
  { label: 'Rotate the ci-bot token', pts: 50, t: (g) => acted(g, 'rotate-secret ci-bot-token') },
  { label: 'Rotate the release-signing key passphrase', pts: 40, t: (g) => acted(g, 'rotate-secret sign-key-pass') },
  { label: 'Lock the forged v3.8.2 tag', pts: 50, t: (g) => [...g.actions].some((x) => x.startsWith('lock ') && x.includes('3.8.2')) },
  { label: `Block ${C2}`, pts: 30, t: (g) => acted(g, `block-domain ${C2}`) },
  { label: `Block ${ATT}`, pts: 15, t: (g) => acted(g, `block-ip ${ATT}`) },
  { label: 'Tell the registry and the real maintainers', pts: 20, t: (g) => acted(g, 'notify vendor') },
  { label: 'Tell the incident-response lead', pts: 15, t: (g) => acted(g, 'notify ir-lead') },
  { label: 'Tell management (a poisoned release reached payments)', pts: 25, t: (g) => acted(g, 'notify management'), when: (g) => !!g.flags.release },
]
const WRONG: Wrong[] = [
  { label: 'Isolated ravi.t\'s laptop (official nvm installer)', pts: -40, t: (g) => acted(g, 'isolate dev-lap-04') },
  { label: 'Disabled kat.o (approved history rewrite)', pts: -30, t: (g) => acted(g, 'disable-user kat.o') },
  { label: 'Blocked the CI runner IP (all builds fail)', pts: -80, t: (g) => acted(g, `block-ip ${RUNNER}`) },
  { label: 'Disabled li.w (merged a routine dependency PR)', pts: -30, t: (g) => acted(g, 'disable-user li.w') },
]
const CHECKS: Record<string, (g: GameView) => boolean> = {
  c_ask: (g) => did(g, /^(ask-it\s.*(nvm|node|wsl|runner|disk|space|ci)|phone\s+(ravi\.t|ana\.v))/i),
  c_ticket: (g) => did(g, /^ticket\s+chg-fp-4/i) || did(g, /^(ask-it\s.*(force|docs|csv)|phone\s+kat\.o)/i),
}
function timeline(k: Set<string>, g: GameView): TimelineRow[] {
  const rows: TimelineRow[] = [
    { at: hm(6, 10), text: 'fenwick-utils-core 2.4.1 is published by a newly added maintainer', ttp: 'T1195.001 Compromise software dependencies', found: k.has('e_pkg') },
    { at: hm(9, 41), text: 'Build #8841 installs it; the postinstall script reads CI secrets', ttp: 'T1059.007 / T1552.001 Credentials in environment', found: k.has('e_postinstall') },
    { at: hm(9, 42), text: 'The secrets are posted to telemetry-npm-cdn.com', ttp: 'T1041 Exfiltration over C2 channel', found: k.has('e_egress') },
    { at: hm(10, 5), text: 'The attacker uses the stolen bot token to modify deploy.sh and tag a signed v3.8.2', ttp: 'T1078 Valid accounts / T1195.002 Supply chain', found: k.has('e_push') || k.has('e_release') },
  ]
  if (g.flags.release) rows.push({ at: hm(11, 41), text: 'The tag triggers a production deploy to 12 payment hosts', ttp: 'T1195.002 Compromise software supply chain', found: k.has('e_deploy') })
  return rows
}
export const shift8: ShiftDef = {
  id: 'soc-8',
  title: 'Fenwick Pay: the postinstall script',
  company: 'Fenwick Pay',
  level: 'Hard',
  blurb: 'A hijacked dependency steals pipeline secrets and forges a signed release. Plenty of the noise is routine developer activity. Production deploys at 11:40.',
  intro: 'You are the security analyst for Fenwick Pay, a fictional 120-person payments company, from 10:30 to 13:00. Source control, CI and the package registry are your sources. The release pipeline runs on a bot token that cannot be trusted any more once you find the theft.',
  start: hm(10, 30), end: hm(13, 0), dates: ['08-04', '08-05'],
  fields: FIELDS, srcdesc: SRCDESC, users: USERS, build, alerts: ALERTS, evd: EVD,
  intel: { ti: TI, whois: WHOIS, phone: PHONE, badge: {}, hr: HR, tickets: TICKET, askIt: askIT, protectedIps: { [RUNNER]: 'this is the CI runner egress. Every build and deploy fails.' } },
  callable: ['ravi.t', 'kat.o', 'li.w', 'ana.v'],
  triggers: [{
    flag: 'release', at: hm(11, 40),
    contained: (g) => acted(g, 'rotate-secret ci-bot-token') && [...g.actions].some((x) => x.startsWith('lock ') && x.includes('3.8.2')),
    penalty: 150, penaltyLabel: 'Forged release deployed to production', okLog: 'Token rotated and v3.8.2 locked before 11:40',
    note: (done, happened) => (!done ? 'The shift ended before 11:40.' : happened ? 'The forged v3.8.2 tag deployed to 12 production hosts because the bot token was not rotated and the tag was not locked.' : 'You rotated the token and locked the tag before the pipeline deployed it.'),
  }],
  contain: CONTAIN, wrong: WRONG, checks: CHECKS, timeline,
  gaps: ['A new maintainer was added to a critical package with no review.', 'Builds ran with install scripts enabled and with all secrets in the environment.', 'CI had open egress, not a registry allow-list.', 'The bot token worked from any IP and could tag releases.', 'Production deploys did not require a second human approval.', 'Dependency updates were merged automatically.'],
  noteTail: defaultNoteTail,
  chips: ['help', 'source=ci event=postinstall', 'source=git user=ci-bot | sort time | table time,ip,event,ref,detail', 'source=registry pkg=fenwick-utils-core', `ti ${C2}`],
  cheat: `source=ci event=postinstall
source=git user=ci-bot | table time,ip,event,ref
source=registry pkg=fenwick-utils-core
source=ci event=net
ti telemetry-npm-cdn.com     ticket chg-fp-4
rotate-secret ci-bot-token     lock v3.8.2     notify vendor     help`,
  solution: {
    cmds: ['rotate-secret ci-bot-token', 'rotate-secret sign-key-pass', 'lock v3.8.2', `block-domain ${C2}`, `block-ip ${ATT}`, 'notify vendor', 'notify ir-lead', 'ticket chg-fp-4', 'ask-it nvm node wsl', 'ask-it runner-3 disk space'],
    verdicts: [['H1', 'incident'], ['H2', 'incident'], ['H3', 'incident'], ['H4', 'benign'], ['H5', 'benign'], ['H6', 'it'], ['H7', 'it']],
    pins: { H1: ['e_postinstall', 'e_egress'], H2: ['e_pkg', 'e_postinstall'], H3: ['e_push', 'e_release'], H4: ['e_nvm'], H5: ['e_force'], H6: ['e_ci_fail'], H7: ['e_advisory'] },
  },
}
