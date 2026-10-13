// Extra alerts for shift 3 (Tidewater Books, 08:00-09:30).
import { hm, m } from '../common'
import type { Noise } from '../noise'

export const noise3: Noise[] = [
  { id: 'Q301', title: 'USB: unknown drive connected on a till', sev: 'med', src: 'Device control', ent: 'SHOP2-PC1', at: hm(8, 20), sla: m(60),
    rule: 'Removable drive with an unrecognised vendor connected.',
    kv: [['Host', 'SHOP2-PC1 (ivy.c)'], ['Drive', 'KINGSTON DataTraveler'], ['Action', 'allowed (read-only policy)']],
    best: 'benign', alt: { fp: 60, it: 50 }, evText: 'The read-only drive connected by the shop manager',
    events: [{ src: 'usb', t: hm(8, 16, 30), f: { host: 'SHOP2-PC1', user: 'ivy.c', drive: 'E:', vendor: 'KINGSTON DataTraveler', action: 'mounted read-only' } }],
    phone: ['ivy.c', 'Ivy C.:\n"That is the stick from the till supplier with the new price list. I only opened the spreadsheet."'],
    why: 'The shop manager plugged in a price-list stick from a till supplier. Policy mounted it read-only and nothing ran from it. Compare it with the found USB stick in the main alert.',
    hints: ['Did anything execute from the drive? Search edr for the host.'] },
  { id: 'Q302', title: 'Proxy: traffic to an uncategorised domain', sev: 'low', src: 'Web proxy', ent: 'MKT-PC2', at: hm(8, 35), sla: m(90),
    rule: 'Request to a domain with no reputation category.',
    kv: [['User', 'ned.f (Marketing)'], ['Domain', 'bookfair-uk.example'], ['Category', 'uncategorized'], ['Age', '41 days']],
    best: 'benign', alt: { fp: 60 }, evText: 'The request to the book-fair site',
    events: [{ src: 'proxy', t: hm(8, 31, 9), f: { user: 'ned.f', host: 'MKT-PC2', src: '10.60.20.34', method: 'GET', domain: 'bookfair-uk.example', url: '/exhibitors', bytes_out: 340, cat: 'uncategorized', age: 41, action: 'allowed' } }],
    ask: [/book.?fair|bookfair|exhibitor/i, 'IT: Marketing are booking a stall at the autumn book fair, that is the organiser site.'],
    why: 'A small GET to the organiser of an event Marketing is booking. Uncategorised is not the same as malicious.',
    hints: ['Is there a business reason? Try ask-it.'] },
  { id: 'Q303', title: 'Entra ID: sign-in from a new device', sev: 'low', src: 'Entra ID', ent: 'bea.s', at: hm(8, 50), sla: m(90),
    rule: 'Sign-in from a device not seen before.',
    kv: [['User', 'bea.s (Management)'], ['Device', 'new'], ['Location', 'Bristol, GB'], ['MFA', 'passed']],
    best: 'benign', alt: { fp: 60 }, evText: 'The sign-in from a new phone with MFA passed',
    events: [{ src: 'entra', t: hm(8, 46, 20), f: { user: 'bea.s', ip: '203.0.113.31', geo: 'Bristol,GB', app: 'Outlook Mobile', dev: 'new-iphone', result: 'success', mfa: 'passed' } }],
    phone: ['bea.s', 'Bea S.:\n"Yes, new phone, I set it up last night. Is that a problem?"'],
    why: 'A manager upgraded her phone and passed MFA from her usual region. Calling her settles it in a minute.',
    hints: ['Phone the user; check the MFA result.'] },
]
