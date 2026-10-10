import { useEffect, useState } from 'react'
import { api, errText, type Idea, type Quiz, type Today as TodayData } from './api'
import { StoryCard } from './StoryCard'
import { IntelWall } from './ops'
import { CountUp, FunFact, Pulse } from './fx'
import type { Page } from './App'

interface Props {
  data: TodayData
  aiReady: boolean
  reload: () => Promise<void>
  go: (p: Page) => void
}

export function Today({ data, aiReady, reload, go }: Props) {
  const firstUnread = data.stories.findIndex((s) => !s.read)
  const [openIdx, setOpenIdx] = useState(firstUnread === -1 ? 0 : firstUnread)
  const [deeper, setDeeper] = useState(false)
  const [quiz, setQuiz] = useState<Quiz | null>(data.quiz)
  const [err, setErr] = useState<string | null>(null)

  const total = data.stories.length
  const pct = total ? Math.round((data.read_count / total) * 100) : 0

  const read = async (i: number) => {
    try {
      await api.markRead(data.stories[i].id)
      await reload()
      const next = data.stories.findIndex((s, j) => j > i && !s.read)
      if (next !== -1) setOpenIdx(next)
    } catch (e) {
      setErr(errText(e))
    }
  }

  const ideaAction = async (fn: () => Promise<unknown>) => {
    try {
      await fn()
      await reload()
    } catch (e) {
      setErr(errText(e))
    }
  }

  const p = data.project
  const stepsDone = p ? p.done.filter(Boolean).length : 0

  const hour = new Date().getHours()
  const greeting = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening'
  const unread = total - data.read_count
  const [name, setName] = useState('')
  useEffect(() => { api.getName().then(setName).catch(() => {}) }, [])

  return (
    <div className="today">
      <div className="greet">
        <Pulse />
        <span className="greet-hi">{greeting}{name ? `, ${name}` : ''}.</span>{' '}
        <span className="muted">
          {total === 0 ? 'Press Refresh to load the news.' : unread === 0 ? "You're all caught up." : `${unread} ${unread === 1 ? 'story' : 'stories'} to read`}
          {data.new_today > 0 && ` · +${data.new_today} new stories today`}
        </span>
      </div>
      {data.stories.length > 0 && (
        <div className="ticker" aria-hidden="true">
          <span className="mono tiny accent">LATEST</span>
          <div className="ticker-track">
            <span className="ticker-run">{data.stories.map((s) => s.headline).join('   ·   ')}</span>
          </div>
        </div>
      )}
      <div className="status-strip mono">
        <div><span className="muted">BRIEF </span>{data.read_count} / {total} READ</div>
        <div className="bar" aria-label={`${pct}% of today's brief read`}><div className="bar-fill" style={{ width: `${pct}%` }} /></div>
        <div><span className="muted">KEV ADDED (7D) </span><span className="red"><CountUp to={data.exploited_recent} /></span></div>
        <div><span className="muted">WATCHLIST HITS </span><span className="amber"><CountUp to={data.watch_hits} /></span></div>
        <div><span className="muted">STREAK </span><span className="accent">{data.streak} {data.streak === 1 ? 'DAY' : 'DAYS'}</span></div>
      </div>
      {err && <div className="error">{err}</div>}

      <div className="grid">
        <section className="panel brief">
          <div className="panel-head">
            <h2 className="mono h2">TODAY'S BRIEF · {total} ITEMS</h2>
            <div className="seg" role="group" aria-label="Reading level">
              <button type="button" className={!deeper ? 'seg-on' : ''} aria-pressed={!deeper} onClick={() => setDeeper(false)}>Simple</button>
              <button type="button" className={deeper ? 'seg-on' : ''} aria-pressed={deeper} onClick={() => setDeeper(true)}>Deeper</button>
            </div>
          </div>
          {total === 0 && (
            <div className="empty">
              <p>No stories yet. Press <strong>Refresh</strong> to fetch today's news.</p>
            </div>
          )}
          {data.stories.map((s, i) => (
            <StoryCard
              key={s.id}
              story={s}
              index={i}
              open={openIdx === i}
              deeper={deeper}
              aiReady={aiReady}
              hasNext={data.stories.some((x, j) => j > i && !x.read)}
              onOpen={() => setOpenIdx(i)}
              onRead={() => void read(i)}
            />
          ))}
          {total > 0 && data.read_count === total && (
            <div className="done-note">That's it for today. Nothing else needs your attention.</div>
          )}
        </section>

        <div className="side">
          {p && (
            <section className="panel panel-accent">
              <div className="panel-row mono small"><span className="accent">PROJECT OF THE WEEK</span><span className="muted">{p.week.split('-')[1]}</span></div>
              <div className="side-title">{p.plan.title}</div>
              <div className="muted small">{p.plan.why}</div>
              <ul className="steps">
                {p.plan.steps.map((s, i) => (
                  <li key={i} className={p.done[i] ? 'step-done' : ''}><span aria-hidden="true">{p.done[i] ? '✓' : '○'}</span> {s}</li>
                ))}
              </ul>
              <div className="bar"><div className="bar-fill" style={{ width: `${(stepsDone / p.plan.steps.length) * 100}%` }} /></div>
              <button type="button" className="linkish small" onClick={() => go('project')}>{p.completed ? 'Built ✓  View project →' : 'Open project →'}</button>
            </section>
          )}

          <section className="panel">
            <div className="panel-row mono small"><span className="muted">IDEA BACKLOG</span><span>{data.idea_count} / {data.idea_cap}</span></div>
            {data.ideas.length === 0 && <div className="muted small">Ideas from the news land here. Keep the good ones, dismiss the rest.</div>}
            {data.ideas.map((i: Idea) => (
              <div key={i.id} className="idea">
                <div className="idea-text">
                  <div className="small">{i.title}</div>
                  <div className={`tiny ${i.expires_in_days !== null && i.expires_in_days <= 3 ? 'amber' : 'muted'}`}>
                    {i.starred ? 'Starred · kept' : `Expires in ${i.expires_in_days} days`}
                  </div>
                </div>
                <button type="button" className={`icon-btn ${i.starred ? 'on' : ''}`} aria-label={i.starred ? 'Unstar idea' : 'Keep idea'} aria-pressed={i.starred} onClick={() => void ideaAction(() => api.starIdea(i.id, !i.starred))}>★</button>
                <button type="button" className="icon-btn" aria-label="Dismiss idea" onClick={() => void ideaAction(() => api.dismissIdea(i.id))}>✕</button>
              </div>
            ))}
            {data.idea_count > 3 && <button type="button" className="linkish small" onClick={() => go('backlog')}>See all {data.idea_count} →</button>}
          </section>

          <section className="panel">
            <div className="mono small muted">TERM OF THE DAY</div>
            <div className="side-title">{data.term.term}</div>
            <div className="muted small">{data.term.plain}</div>
            {data.term.analogy && <div className="small analogy">Think of it as: {data.term.analogy}</div>}
          </section>

          <FunFact />

          <IntelWall go={go} />

          {quiz && (
            <section className="panel">
              <div className="mono small muted">QUICK CHECK</div>
              <div className="small">{quiz.question}</div>
              <div className="quiz-opts">
                {quiz.options.map((o, i) => {
                  const state = quiz.answer === null ? '' : i === quiz.answer ? 'opt-right' : i === quiz.chosen ? 'opt-wrong' : ''
                  return (
                    <button
                      key={i}
                      type="button"
                      className={`opt ${state}`}
                      disabled={quiz.chosen !== null}
                      onClick={() => api.answerQuiz(i).then(setQuiz).catch((e) => setErr(errText(e)))}
                    >
                      {o}
                    </button>
                  )
                })}
              </div>
              {quiz.explanation && <div className="small muted">{quiz.chosen === quiz.answer ? 'Correct. ' : 'Not quite. '}{quiz.explanation}</div>}
            </section>
          )}
        </div>
      </div>

      <div className="grid-2">
        <section className="panel teaser">
          <div>
            <div className="mono small muted">WEEKLY RECAP · SUNDAY</div>
            <div className="small muted">Top 3 themes of the week plus 3 quiz questions.</div>
          </div>
          <button type="button" className="linkish small" onClick={() => go('recap')}>
            {data.recap_days_until === 0 ? 'Ready: open →' : `Ready in ${data.recap_days_until} days · preview →`}
          </button>
        </section>
        <section className="panel teaser">
          <div>
            <div className="mono small muted">SKILLS RADAR · 30 DAYS</div>
            <div className="small muted">
              Trending: {data.radar_top.filter((r) => r.mentions > 0).map((r) => r.theme).join(' · ') || 'building up…'}
            </div>
          </div>
          <button type="button" className="linkish small" onClick={() => go('radar')}>Open radar →</button>
        </section>
      </div>
    </div>
  )
}
