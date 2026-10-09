import { useCallback, useEffect, useRef, useState } from 'react'
import { api, errText, type Today as TodayData } from './api'
import { Today } from './Today'
import { BacklogPage, BuiltPage, GlossaryPage, IntelPage, ProjectPage, RadarPage, RecapPage, SettingsPage, WatchlistPage } from './pages'
import { LiveOpsPage } from './LiveOps'
import { loadAnimations } from './prefs'
import { briefScript, playParts, stopSpeaking } from './listen'

export type Page = 'today' | 'project' | 'backlog' | 'built' | 'recap' | 'radar' | 'glossary' | 'intel' | 'liveops' | 'watchlist' | 'settings'

const NAV: { id: Page; label: string; group?: 'top' | 'mid' | 'bottom' }[] = [
  { id: 'today', label: 'TODAY', group: 'top' },
  { id: 'liveops', label: 'LIVE OPS', group: 'top' },
  { id: 'project', label: 'PROJECT OF WEEK', group: 'top' },
  { id: 'backlog', label: 'BACKLOG', group: 'top' },
  { id: 'built', label: 'BUILT', group: 'top' },
  { id: 'recap', label: 'WEEKLY RECAP', group: 'mid' },
  { id: 'radar', label: 'SKILLS RADAR', group: 'mid' },
  { id: 'intel', label: 'INTEL', group: 'mid' },
  { id: 'glossary', label: 'GLOSSARY', group: 'mid' },
  { id: 'watchlist', label: 'WATCHLIST', group: 'bottom' },
  { id: 'settings', label: 'SETTINGS', group: 'bottom' },
]

function syncText(ts: number): string {
  if (!ts) return 'NOT SYNCED YET'
  const m = Math.round((Date.now() / 1000 - ts) / 60)
  if (m < 1) return 'SYNCED JUST NOW'
  if (m < 120) return `SYNCED ${m} MIN AGO`
  return `SYNCED ${Math.round(m / 60)}H AGO`
}

export default function App() {
  const [page, setPage] = useState<Page>('today')
  const [today, setToday] = useState<TodayData | null>(null)
  const [aiReady, setAiReady] = useState(false)
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<string | null>(null)
  const [speaking, setSpeaking] = useState(false)
  const enhancing = useRef(false)

  const reload = useCallback(async () => {
    try {
      setToday(await api.today())
    } catch (e) {
      setNote(errText(e))
    }
  }, [])

  const checkAi = useCallback(async () => {
    try {
      const s = await api.aiStatus()
      setAiReady(s.running && s.enabled && s.models.length > 0)
    } catch {
      setAiReady(false)
    }
  }, [])

  // Rewrite today's stories with the local AI, one at a time, in the background.
  const enhance = useCallback(async (data: TodayData | null) => {
    if (!data || enhancing.current) return
    enhancing.current = true
    try {
      for (const s of data.stories.filter((x) => !x.ai)) {
        try {
          const card = await api.enhance(s.id)
          setToday((t) => (t ? { ...t, stories: t.stories.map((x) => (x.id === card.id ? card : x)) } : t))
        } catch {
          break // AI unavailable or failed: keep the source summaries
        }
      }
    } finally {
      enhancing.current = false
    }
  }, [])

  const refresh = useCallback(async (force: boolean) => {
    setBusy(true)
    setNote(null)
    try {
      const r = await api.refresh(force)
      if (r.skipped && force) setNote('Already up to date. Try again in a couple of minutes.')
      else if (r.failed.length) setNote(`Couldn't reach: ${r.failed.join(', ')}. Using what we have.`)
      await reload()
    } catch (e) {
      setNote(errText(e))
    } finally {
      setBusy(false)
    }
  }, [reload])

  useEffect(() => {
    void (async () => {
      await reload()
      await checkAi()
      await refresh(false)
    })()
    const timer = window.setInterval(() => void refresh(false), 30 * 60 * 1000)
    return () => window.clearInterval(timer)
  }, [reload, checkAi, refresh])

  useEffect(() => {
    void loadAnimations()
  }, [])

  useEffect(() => {
    if (aiReady && today) void enhance(today)
  }, [aiReady, today?.day, today?.stories.length]) // eslint-disable-line react-hooks/exhaustive-deps

  const listen = async () => {
    if (speaking) {
      stopSpeaking()
      setSpeaking(false)
      return
    }
    if (!today?.stories.length) return
    setSpeaking(true)
    const ok = await playParts(briefScript(today.stories), () => setSpeaking(false))
    if (!ok) {
      setSpeaking(false)
      setNote('No private voice found. Install the natural voice in Settings → Voice.')
    }
  }

  const date = new Date().toLocaleDateString('en-GB', { weekday: 'short', day: '2-digit', month: 'short', year: 'numeric' }).toUpperCase()
  const minutes = Math.max(1, (today?.stories.length ?? 0) + 1)

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" className="brand-icon" aria-hidden="true"><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="4" /><line x1="12" y1="3" x2="12" y2="7" /></svg>
          <span className="mono brand-name">SITREP</span>
        </div>
        <div className="mono small muted">{date}</div>
        <div className="spacer" />
        <div className="mono small muted sync"><span className={`dot ${busy ? 'dot-busy' : ''}`} />{busy ? 'SYNCING…' : syncText(today?.last_sync ?? 0)}</div>
        <button type="button" className="btn" disabled={busy} onClick={() => void refresh(true)}>Refresh</button>
        <button type="button" className="btn btn-primary" onClick={() => void listen()} disabled={!today?.stories.length}>
          {speaking ? '■ Stop' : `▶ Listen to brief · ${minutes} min`}
        </button>
      </header>

      <div className="body">
        <nav className="rail mono" aria-label="Main">
          {NAV.map((n, i) => (
            <div key={n.id} className="rail-item-wrap">
              {i > 0 && NAV[i - 1].group !== n.group && <div className={n.group === 'bottom' ? 'rail-push' : 'rail-sep'} />}
              <button
                type="button"
                className={`rail-item ${page === n.id ? 'rail-on' : ''}`}
                aria-current={page === n.id ? 'page' : undefined}
                onClick={() => setPage(n.id)}
              >
                {n.label}
                {n.id === 'backlog' && today && <span className="muted">{today.idea_count}/{today.idea_cap}</span>}
              </button>
            </div>
          ))}
        </nav>

        <main className="main">
          {note && <div className="note" role="status">{note}</div>}
          {page === 'today' && (today ? <Today data={today} aiReady={aiReady} reload={reload} go={setPage} /> : <div className="muted">Loading…</div>)}
          {page === 'project' && <ProjectPage />}
          {page === 'backlog' && <BacklogPage />}
          {page === 'built' && <BuiltPage />}
          {page === 'recap' && <RecapPage />}
          {page === 'radar' && <RadarPage />}
          {page === 'glossary' && <GlossaryPage />}
          {page === 'intel' && <IntelPage />}
          {page === 'liveops' && <LiveOpsPage onOpenStory={() => setPage('today')} />}
          {page === 'watchlist' && <WatchlistPage onChange={() => void reload()} />}
          {page === 'settings' && <SettingsPage onAiChange={() => void checkAi()} />}
        </main>
      </div>

      <footer className="footer mono small muted">
        <span>NEXT AUTO-SYNC · EVERY 30 MIN WHILE OPEN</span>
        <span>WATCHLIST · {today?.watchlist.length ? today.watchlist.slice(0, 5).map((w) => `[${w.toUpperCase()}]`).join(' ') : 'EMPTY'}</span>
        <span>LOCAL ONLY · NO TRACKING</span>
      </footer>
    </div>
  )
}
