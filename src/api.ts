// Typed wrappers around the Rust commands. The UI has no other way to reach
// the network, the filesystem or the database.
import { invoke } from '@tauri-apps/api/core'

export type Category = 'exploited_now' | 'big_incident' | 'uk' | 'news'

export interface Term { term: string; plain: string; analogy?: string }

export interface Story {
  id: string
  category: Category
  category_label: string
  sources: string[]
  published: number
  original_title: string
  headline: string
  tldr: string
  why: string
  deeper: string
  gist: string
  plain: string
  action: string
  roles: { role: string; note: string }[]
  cvss: { cve: string; score: number; severity: string; exploited: boolean }[]
  developing: { id: string; title: string; source: string; published: number; why: string }[]
  actors: string[]
  terms: { term: string; plain: string }[]
  cves: string[]
  watch_hits: string[]
  ai: boolean
  read: boolean
  has_link: boolean
}

export interface GlossEntry { key: string; term: string; plain: string; analogy: string; status: 'new' | 'learning' | 'known'; origin: 'builtin' | 'ai' }
export interface ActorSeen { name: string; kind: string; origin: string; country: string; blurb: string; stories: [string, string][] }
export interface Exposure { program: string; vendor: string; product: string; cves: string[]; latest_added: string; ransomware: boolean }
export interface ExposureResult { supported: boolean; programs: number; window_days: number; matches: Exposure[] }
export interface LabPackResult { folder: string; ips: number; domains: number; hashes: number }

export interface Quiz {
  day: string
  question: string
  options: string[]
  chosen: number | null
  answer: number | null
  explanation: string | null
}

export interface ProjectPlan {
  theme: string
  title: string
  why: string
  tools: string[]
  steps: string[]
  done_when: string
}

export interface Project {
  week: string
  plan: ProjectPlan
  done: boolean[]
  completed: boolean
  completed_at: number | null
}

export interface Idea {
  id: number
  title: string
  detail: string
  theme: string
  created: number
  starred: boolean
  status: 'active' | 'archived'
  reason: string | null
  expires_in_days: number | null
}

export interface RadarRow { theme: string; key: string; mentions: number; built: boolean }

export interface Today {
  day: string
  last_sync: number
  stories: Story[]
  read_count: number
  exploited_recent: number
  watch_hits: number
  streak: number
  new_today: number
  term: Term
  quiz: Quiz | null
  project: Project | null
  ideas: Idea[]
  idea_count: number
  idea_cap: number
  recap_days_until: number
  radar_top: RadarRow[]
  watchlist: string[]
}

export interface LiveOps {
  map: {
    nodes: { id: string; name: string; lat: number; lon: number; count: number; stories: [string, string][] }[]
    arcs: { actor: string; from: string; to: string; count: number }[]
    edges: { actor: string; cve: string }[]
    stories_considered: number
  }
  cves: { cve: string; first_seen: number; exploited_on: string | null; ransomware: boolean; score: number | null; severity: string | null; fix_mentioned: boolean; stories: number; headline: string }[]
  calendar: string[]
  today: string
  streak: number
  exploited_14d: number
  new_today: number
}

export interface Recap {
  ready: boolean
  days_until: number
  story_count: number
  themes: { theme: string; count: number; examples: string[] }[]
  questions: { question: string; options: string[]; answer: number; explanation: string }[]
}

export interface BuiltItem { week: string; title: string; theme: string; completed_at: number }
export interface AiStatus { running: boolean; enabled: boolean; models: string[]; model: string; full_articles: boolean }
export interface UpdateInfo { current: string; available: string | null; notes: string | null }
export interface VoiceStatus { installed: boolean; voice: string; size_mb: number; sample_rate: number }
export interface RefreshResult { new_stories: number; failed: string[]; skipped: boolean }

export const api = {
  refresh: (force = false) => invoke<RefreshResult>('refresh', { force }),
  today: () => invoke<Today>('get_today'),
  markRead: (id: string) => invoke<void>('mark_read', { id }),
  openStory: (id: string) => invoke<void>('open_story', { id }),
  aiStatus: () => invoke<AiStatus>('ai_status'),
  setAi: (enabled: boolean, model: string) => invoke<void>('set_ai', { enabled, model }),
  setFullArticles: (enabled: boolean) => invoke<void>('set_full_articles', { enabled }),
  enhance: (id: string) => invoke<Story>('enhance_story', { id }),
  ask: (id: string, question: string) => invoke<string>('ask_story', { id, question }),
  ideas: (status: 'active' | 'archived') => invoke<Idea[]>('list_ideas', { status }),
  starIdea: (id: number, starred: boolean) => invoke<void>('star_idea', { id, starred }),
  dismissIdea: (id: number) => invoke<void>('dismiss_idea', { id }),
  restoreIdea: (id: number) => invoke<boolean>('restore_idea', { id }),
  deleteIdea: (id: number) => invoke<void>('delete_idea', { id }),
  project: () => invoke<Project | null>('get_project'),
  toggleStep: (step: number) => invoke<Project | null>('toggle_project_step', { step }),
  completeProject: (completed: boolean) => invoke<Project | null>('complete_project', { completed }),
  built: () => invoke<BuiltItem[]>('list_built'),
  glossary: () => invoke<GlossEntry[]>('get_glossary'),
  setTermStatus: (key: string, status: string) => invoke<GlossEntry[]>('set_term_status', { key, status }),
  getAnimations: () => invoke<boolean>('get_animations'),
  setAnimations: (on: boolean) => invoke<void>('set_animations', { on }),
  liveops: () => invoke<LiveOps>('get_liveops'),
  actors: () => invoke<ActorSeen[]>('get_actors'),
  exposure: () => invoke<ExposureResult>('check_exposure'),
  labPack: (id: string) => invoke<LabPackResult>('export_lab_pack', { id }),
  answerQuiz: (choice: number) => invoke<Quiz | null>('answer_quiz', { choice }),
  recap: () => invoke<Recap>('get_recap'),
  radar: () => invoke<RadarRow[]>('get_radar'),
  watchlist: () => invoke<string[]>('get_watchlist'),
  addWatch: (term: string) => invoke<string[]>('add_watch', { term }),
  removeWatch: (term: string) => invoke<string[]>('remove_watch', { term }),
  focus: () => invoke<string[]>('get_focus'),
  setFocus: (roles: string[]) => invoke<string[]>('set_focus', { roles }),
  focusOptions: () => invoke<string[]>('focus_options'),
  voiceStatus: () => invoke<VoiceStatus>('voice_status'),
  voiceInstall: () => invoke<VoiceStatus>('voice_install'),
  voiceRemove: () => invoke<VoiceStatus>('voice_remove'),
  speakPiper: (parts: string[]) => invoke<ArrayBuffer>('speak_piper', { parts }),
  appVersion: () => invoke<string>('app_version'),
  checkUpdate: () => invoke<UpdateInfo>('check_update'),
  installUpdate: () => invoke<void>('install_update'),
  sources: () => invoke<{ name: string; url: string }[]>('list_sources'),
}

export function errText(e: unknown): string {
  return typeof e === 'string' ? e : 'Something went wrong.'
}
