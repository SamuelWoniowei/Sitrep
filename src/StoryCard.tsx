import { useState } from 'react'
import { api, errText, type Story } from './api'

const TAG: Record<Story['category'], string> = {
  exploited_now: 'tag tag-red',
  big_incident: 'tag tag-amber',
  uk: 'tag tag-blue',
  news: 'tag tag-grey',
}

// Splits the summary into up to four steps and lights them one after another.
const STAGES: { label: string; words: RegExp }[] = [
  { label: 'Get in', words: /phish|exploit|vulnerab|zero-day|credential|stolen|brute|vpn|rdp|supply.chain|malicious|compromis|breach/i },
  { label: 'Run code', words: /execut|malware|payload|script|powershell|loader|backdoor|trojan|install|remote code/i },
  { label: 'Stay hidden', words: /persist|implant|escalat|privilege|evad|disable|hidden|stealth/i },
  { label: 'Spread', words: /lateral|spread|move[sd]? (?:to|across|through)|domain controller|active directory|pivot|worm/i },
  { label: 'Cause harm', words: /ransom|encrypt|exfiltrat|steal|leak|wiper|destroy|extort|outage|data theft|disrupt/i },
]

/** A rough attack chain, lit up from words in the story. Not a full incident report. */
function AttackFlow({ story }: { story: Story }) {
  const text = [story.headline, story.tldr, story.why, story.gist, story.plain, story.deeper].join(' ')
  const hits = STAGES.map((s) => s.words.test(text))
  if (hits.filter(Boolean).length < 2) return null
  let n = 0
  return (
    <div className="deeper">
      <div className="label">HOW THE ATTACK WORKED</div>
      <ol className="flow" aria-label="Attack stages found in this story">
        {STAGES.map((st, i) => {
          const on = hits[i]
          const delay = on ? n++ * 0.6 : 0
          return (
            <li key={st.label} className={`flow-step ${on ? 'flow-on' : ''}`} style={{ animationDelay: `${delay}s`, ['--d' as string]: delay }}>
              <span className="flow-dot" />
              <span className="small">{st.label}</span>
              <span className="tiny muted">{on ? 'in this story' : 'not mentioned'}</span>
            </li>
          )
        })}
      </ol>
      <p className="tiny muted">Estimated from the words in the story, so it is a guide, not a full account of the attack.</p>
    </div>
  )
}

function Storyboard({ text }: { text: string }) {
  const steps = (text.match(/[^.!?]+[.!?]+/g) ?? [text]).map((x) => x.trim()).filter(Boolean).slice(0, 4)
  if (steps.length < 2) return null
  const names = ['What happened', 'The weakness', 'The impact', 'The fix']
  return (
    <ol className="board" aria-label="Step by step">
      {steps.map((st, i) => (
        <li key={i} className="board-step">
          <span className="board-n mono">{i + 1}</span>
          <div><div className="mono tiny accent">{(steps.length === 4 ? names[i] : `Step ${i + 1}`).toUpperCase()}</div><div className="small">{st}</div></div>
        </li>
      ))}
    </ol>
  )
}

function ago(ts: number): string {
  const h = Math.max(0, Math.round((Date.now() / 1000 - ts) / 3600))
  if (h < 1) return 'just now'
  if (h < 48) return `${h}h ago`
  return `${Math.round(h / 24)}d ago`
}

interface Props {
  story: Story
  index: number
  open: boolean
  deeper: boolean
  aiReady: boolean
  hasNext: boolean
  onOpen: () => void
  onRead: () => void
}

// All text is rendered as React text nodes (auto-escaped). This component,
// like the rest of the UI, never renders HTML.
export function StoryCard({ story, index, open, deeper, aiReady, hasNext, onOpen, onRead }: Props) {
  const [term, setTerm] = useState<string | null>(null)
  const [question, setQuestion] = useState('')
  const [answer, setAnswer] = useState<string | null>(null)
  const [asking, setAsking] = useState(false)
  const [linkErr, setLinkErr] = useState<string | null>(null)
  const [pack, setPack] = useState<string | null>(null)
  const num = String(index + 1).padStart(2, '0')

  const ask = async () => {
    if (question.trim().length < 3) return
    setAsking(true)
    setAnswer(null)
    try {
      setAnswer(await api.ask(story.id, question.trim()))
    } catch (e) {
      setAnswer(errText(e))
    } finally {
      setAsking(false)
    }
  }

  const shown = story.terms.find((t) => t.term === term)

  return (
    <article className={`story ${open ? 'story-open' : ''}`}>
      <div className="story-meta">
        <span className={TAG[story.category]}>{num} · {story.category_label}</span>
        {story.watch_hits.length > 0 && <span className="tag tag-amber">ON YOUR WATCHLIST</span>}
        {story.read && <span className="tag tag-green">READ</span>}
        <span className="muted small">
          {story.sources[0]}{story.sources.length > 1 ? ` + ${story.sources.length - 1} more` : ''} · {ago(story.published)}
        </span>
      </div>

      {open ? (
        <h3 className="story-title">{story.headline}</h3>
      ) : (
        <h3 className="story-title">
          <button type="button" className="linkish" onClick={onOpen}>{story.headline}</button>
        </h3>
      )}

      {open && (
        <>
          <p><span className="mono accent">TL;DR </span>{story.tldr}</p>
          {story.gist && (deeper ? <Storyboard text={story.gist} /> : <p className="gist">{story.gist}</p>)}
          {story.cvss.length > 0 && (
            <div className="chips">
              {story.cvss.map((c) => (
                <span key={c.cve} className={`tag ${c.severity === 'CRITICAL' || c.exploited ? 'tag-red' : c.severity === 'HIGH' ? 'tag-amber' : 'tag-grey'}`}>
                  {c.cve} · {c.score.toFixed(1)} {c.severity}{c.exploited ? ' · EXPLOITED' : ''}
                </span>
              ))}
            </div>
          )}
          {story.plain && (
            <div className="plain">
              <span className="tag tag-ai" title="Written by your local AI">AI</span> <strong>In plain words: </strong>
              <span className="muted">{story.plain}</span>
            </div>
          )}
          {story.action && <div className="why"><strong>What to do: </strong><span className="muted">{story.action}</span></div>}
          <div className="why"><strong>Why it matters to you: </strong><span className="muted">{story.why}</span></div>
          {story.actors.length > 0 && (
            <div className="chips">
              <span className="muted small">Linked to:</span>
              {story.actors.map((a) => <span key={a} className="tag tag-blue">{a}</span>)}
            </div>
          )}
          {story.developing.length > 0 && (
            <div className="deeper">
              <div className="label">DEVELOPING · {story.developing.length} RELATED</div>
              <ul className="plain-list small">
                {story.developing.map((d) => (
                  <li key={d.id}><span className="muted mono tiny">{new Date(d.published * 1000).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })}</span> {d.title} <span className="muted tiny">· {d.source} · {d.why}</span></li>
                ))}
              </ul>
            </div>
          )}
          {story.roles.length > 0 && (
            <div className="roles">
              {story.roles.map((r) => (
                <div key={r.role} className="role">
                  <div className="mono tiny accent">{r.role.toUpperCase()}</div>
                  <div className="small muted">{r.note}</div>
                </div>
              ))}
            </div>
          )}
          {deeper && (
            <div className="deeper">
              <div className="label">DEEPER</div>
              <p>{story.deeper}</p>
              {story.cves.length > 0 && <p className="mono small">{story.cves.join(' · ')}</p>}
            </div>
          )}
          {deeper && <AttackFlow story={story} />}
          {story.terms.length > 0 && (
            <div className="chips">
              <span className="muted small">Terms:</span>
              {story.terms.map((t) => (
                <button
                  key={t.term}
                  type="button"
                  className={`chip ${term === t.term ? 'chip-on' : ''}`}
                  aria-pressed={term === t.term}
                  onClick={() => setTerm(term === t.term ? null : t.term)}
                >
                  {t.term}
                </button>
              ))}
            </div>
          )}
          {shown && <div className="term-pop"><strong>{shown.term}:</strong> {shown.plain}</div>}

          {aiReady && (
            <form
              className="ask"
              onSubmit={(e) => { e.preventDefault(); void ask() }}
            >
              <label className="ask-field">
                <span className="mono small muted">ASK</span>
                <input
                  type="text"
                  maxLength={300}
                  value={question}
                  onChange={(e) => setQuestion(e.target.value)}
                  placeholder="e.g. How would a SOC detect this?"
                />
              </label>
              <button type="submit" className="btn" disabled={asking || question.trim().length < 3}>
                {asking ? 'Thinking…' : 'Ask'}
              </button>
            </form>
          )}
          {answer && <div className="answer">{answer}</div>}
          {story.ai && <div className="muted tiny">Summary by your local AI. Check the source for anything important.</div>}

          <div className="actions">
            {story.has_link && (
              <button
                type="button"
                className="btn"
                onClick={() => api.openStory(story.id).catch((e) => setLinkErr(errText(e)))}
              >
                Read source
              </button>
            )}
            <button
              type="button"
              className="btn"
              onClick={() => api.labPack(story.id).then((r) => setPack(`Saved to ${r.folder} (${r.ips} IPs, ${r.domains} domains, ${r.hashes} hashes). Drafts for your lab only.`)).catch((e) => setPack(errText(e)))}
            >
              Lab pack
            </button>
            {!story.read && <button type="button" className="btn btn-primary" onClick={onRead}>{hasNext ? 'Got it, next →' : 'Got it'}</button>}
          </div>
          {linkErr && <div className="error small">{linkErr}</div>}
          {pack && <div className="muted small">{pack}</div>}
        </>
      )}
      {!open && <div className="muted small">{story.read ? 'Read.' : 'Tap the headline to open.'}</div>}
    </article>
  )
}
