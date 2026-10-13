// Extra alerts for shift 2 (Wren Dental, 09:00-10:30).
import { hm, m } from '../common'
import type { Noise } from '../noise'

export const noise2: Noise[] = [
  { id: 'Q201', title: 'Proxy: 48 MB upload to a file-sharing site', sev: 'med', src: 'Web proxy', ent: 'BILL-PC1', at: hm(9, 25), sla: m(90),
    rule: 'Outbound POST over 40 MB to a file-sharing site.',
    kv: [['User', 'leo.g (Billing)'], ['Destination', 'secure.cohenaccounts.example'], ['Size', '48 MB'], ['Category', 'file sharing']],
    best: 'benign', alt: { fp: 70 }, evText: 'The upload to the accountants portal',
    events: [{ src: 'proxy', t: hm(9, 21, 40), f: { user: 'leo.g', host: 'BILL-PC1', src: '10.40.19.45', method: 'POST', domain: 'secure.cohenaccounts.example', url: '/upload/month-end', bytes_out: 48000000, cat: 'file sharing', age: 2800, action: 'allowed' } }],
    ask: [/cohen|account|month.?end|upload/i, 'IT: Cohen & Co are the practice accountants. Billing sends them the month-end pack on the 12th every month.'],
    why: 'Month-end accounts go to the practice accountants on the same day every month. Big upload, expected.',
    hints: ['Who owns that domain, and is it a regular supplier? Try ask-it.'] },
  { id: 'Q202', title: 'Entra ID: 3 failed sign-ins from Poland', sev: 'low', src: 'Entra ID', ent: 'zoe.k', at: hm(9, 35), sla: m(120),
    rule: 'Failed sign-ins from a country new for this user.',
    kv: [['User', 'zoe.k'], ['Country', 'Poland (new)'], ['Result', 'failure x3'], ['Success', 'none']],
    best: 'benign', alt: { fp: 60 }, evText: 'Three failures from the same outside IP, no success',
    events: [{ src: 'entra', t: hm(9, 30, 14), f: { user: 'zoe.k', ip: '198.51.100.77', geo: 'Warsaw,PL', app: 'Office365 Web', dev: 'unknown', result: 'failure', mfa: 'n/a' } },
      { src: 'entra', t: hm(9, 30, 52), f: { user: 'zoe.k', ip: '198.51.100.77', geo: 'Warsaw,PL', app: 'Office365 Web', dev: 'unknown', result: 'failure', mfa: 'n/a' } },
      { src: 'entra', t: hm(9, 31, 31), f: { user: 'zoe.k', ip: '198.51.100.77', geo: 'Warsaw,PL', app: 'Office365 Web', dev: 'unknown', result: 'failure', mfa: 'n/a' } }],
    why: 'Three bad guesses from a random address, then nothing. No success, no follow-up. This is internet background noise. Compare it with rita.q, who really was signed in.',
    hints: ['Did any attempt from that address succeed? Search entra for the IP.'] },
  { id: 'Q203', title: 'Mail: macro-enabled attachment quarantined', sev: 'med', src: 'Mail flow', ent: 'ana.s', at: hm(9, 45), sla: m(120),
    rule: 'Inbound message with an Office macro attachment.',
    kv: [['Recipient', 'ana.s'], ['Sender', 'accounts@labwork.example'], ['Attachment', 'case_4471.docm'], ['Gateway', 'quarantined']],
    best: 'it', alt: { benign: 70, fp: 40 }, evText: 'The quarantined message from the dental lab',
    events: [{ src: 'mail', t: hm(9, 41, 3), f: { sender: 'accounts@labwork.example', rcpt: 'ana.s@wrendental.example', subj: 'Lab case 4471 returned', att: 'case_4471.docm', url: '-', dir: 'inbound', verdict: 'quarantined' } }],
    ask: [/lab|case 4471|docm|macro/i, 'IT: the lab usually sends PDFs. A .docm is odd but their sending address is the normal one. Ask them to resend as PDF; we can release it after a scan.'],
    why: 'The gateway already blocked it, so nothing reached the inbox. The lab is a real supplier using an unusual file type, so hand it to IT to confirm and release, and ask the lab for a PDF.',
    hints: ['Was it delivered or quarantined? Is the sender a known supplier?'] },
]
