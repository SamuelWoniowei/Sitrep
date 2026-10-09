import { useState } from 'react'
import { api, errText, type Story } from './api'

const TAG: Record<Story['category'], string> = {
  exploited_now: 'tag tag-red',
  big_incident: 'tag tag-amber',
  uk: 'tag tag-blue',
  news: 'tag tag-grey',
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
  onOpen: () => void
  onRead: () => void
}

// All text is rendered as React text nodes (auto-escaped). This component,
// like the rest of the UI, never renders HTML.
export function StoryCard({ story, index, open, deeper, aiReady, onOpen, onRead }: Props) {
  const [term, setTerm] = useState<string | null>(null)
  const [question, setQuestion] = useState('')
  const [answer, setAnswer] = useState<string | null>(null)
  const [asking, setAsking] = useState(false)
  const [linkErr, setLinkErr] = useState<string | null>(null)
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
          <div className="why"><strong>Why it matters to you: </strong><span className="muted">{story.why}</span></div>
          {deeper && (
            <div className="deeper">
              <div className="label">DEEPER</div>
              <p>{story.deeper}</p>
              {story.cves.length > 0 && <p className="mono small">{story.cves.join(' · ')}</p>}
            </div>
          )}
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
            {!story.read && <button type="button" className="btn btn-primary" onClick={onRead}>Got it</button>}
          </div>
          {linkErr && <div className="error small">{linkErr}</div>}
        </>
      )}
      {!open && <div className="muted small">{story.read ? 'Read.' : 'Tap the headline to open.'}</div>}
    </article>
  )
}
