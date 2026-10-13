// Extra alerts for shift 4 (Kestrel Print Works, 06:30-08:30).
import { hm, m } from '../common'
import type { Noise } from '../noise'

export const noise4: Noise[] = [
  { id: 'Q401', title: 'Firewall: 600 blocked connections from 192.0.2.91', sev: 'low', src: 'Firewall', ent: '192.0.2.91', at: hm(6, 40), sla: m(120),
    rule: 'More than 500 denied connections from one external address in an hour.',
    kv: [['Source', '192.0.2.91'], ['Ports', 'many'], ['Action', 'all denied']],
    best: 'benign', alt: { fp: 60 }, evText: 'The denied scan with no successful connection',
    events: [{ src: 'fw', t: hm(6, 33, 8), f: { src: '192.0.2.91', dst: '203.0.113.51', port: 23, action: 'deny', bytes: 0 } },
      { src: 'fw', t: hm(6, 33, 9), f: { src: '192.0.2.91', dst: '203.0.113.51', port: 2323, action: 'deny', bytes: 0 } }],
    why: 'A scanner knocking on telnet ports, everything denied, nothing allowed. Constant background noise. Compare it with the one address that did reach RDP.',
    hints: ['Were any connections from this address allowed?'] },
  { id: 'Q402', title: 'Backup: nightly job completed with warnings', sev: 'med', src: 'Backup', ent: 'FILE-SRV01', at: hm(6, 50), sla: m(120),
    rule: 'Backup job finished with warnings or skipped files.',
    kv: [['Host', 'FILE-SRV01'], ['Job', 'nightly-files'], ['Result', 'warning'], ['Skipped', '14 open files']],
    best: 'it', alt: { benign: 60 }, evText: 'The warning with 14 skipped open files',
    events: [{ src: 'backup', t: hm(6, 44, 2), f: { host: 'FILE-SRV01', job: 'nightly-files', result: 'warning', detail: 'completed, 14 files skipped (in use)' } }],
    ask: [/backup|nightly|skipped|file-srv/i, 'IT: someone leaves the design archive open overnight, so those files get skipped. Known, but worth raising a ticket to fix it.'],
    why: 'Open files are skipped by the backup. Not an attack, but important to fix before an attack happens. Hand it to IT.',
    hints: ['What does the job detail say was skipped?'] },
  { id: 'Q403', title: 'EDR: remote-support tool installed on PRESS-WS2', sev: 'med', src: 'EDR', ent: 'PRESS-WS2', at: hm(7, 5), sla: m(75),
    rule: 'Remote-administration software installed outside the software catalogue.',
    kv: [['Host', 'PRESS-WS2 (carl.j)'], ['Process', 'rsupport-agent.exe'], ['Signature', 'signed (press vendor)']],
    best: 'benign', alt: { it: 60, fp: 50 }, evText: 'The signed vendor tool installed during a vendor visit',
    events: [{ src: 'edr', t: hm(7, 0, 41), f: { host: 'PRESS-WS2', user: 'carl.j', proc: 'rsupport-agent.exe', parent: 'msiexec.exe', cmd: 'msiexec /i rsupport-agent.msi /qn', action: 'allowed', sig: 'signed' } }],
    ticket: ['tkt-402', 'TKT-402 · Approved · press vendor remote-support agent on PRESS-WS2\nVendor engineer remote session booked 07:00 to 07:30 today.'],
    why: 'The press vendor installed their signed support agent for a booked repair, ticket TKT-402. Remote tools matter because ransomware crews use them too, but this one is approved.',
    hints: ['Check for a ticket on that workstation today.'] },
]
