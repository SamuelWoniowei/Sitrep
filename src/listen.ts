// Listen mode. Two private options, both fully on this computer:
//  1. Piper "Alan" (British male), if installed in Settings. Synthesised by the
//     Rust side; the UI only plays the audio it gets back.
//  2. The operating system's built-in voices, restricted to ones that run
//     on-device. Windows "Online (Natural)" voices send text to Microsoft's
//     servers, so they are never used.
import { api, type Story } from './api'

export function canListen(): boolean {
  return typeof window !== 'undefined' && 'speechSynthesis' in window
}

/** Make text sound right when spoken: no CVE numbers read digit by digit, no links, no brackets. */
export function spoken(t: string): string {
  return t
    .replace(/https?:\/\/\S+/gi, '')
    .replace(/CVE-\d{4}-\d{4,}/gi, 'a tracked flaw')
    .replace(/\s*\([^)]*\)/g, '')
    .replace(/\s+/g, ' ')
    .trim()
}

const ORDINALS = ['First', 'Next', 'Then', 'After that', 'Also']

/** A plain-English spoken briefing: what happened, in simple words, and what to do. Not a reading of the cards. */
export function briefScript(stories: Story[]): string[] {
  const parts = [`Here is your sitrep, in plain English. ${stories.length} ${stories.length === 1 ? 'thing' : 'things'} worth knowing today.`]
  stories.forEach((s, i) => {
    const lead = i === stories.length - 1 && stories.length > 1 ? 'Last' : ORDINALS[Math.min(i, ORDINALS.length - 1)]
    const simple = spoken(s.plain || s.tldr || '')
    const todo = spoken(s.action || '')
    parts.push(
      [`${lead}: ${spoken(s.headline)}.`, simple && `${simple.replace(/[.!?]*$/, '.')}`, todo && `What to do: ${todo.replace(/[.!?]*$/, '.')}`]
        .filter(Boolean)
        .join(' '),
    )
  })
  parts.push("That's your sitrep. Nothing else needs you today.")
  return parts
}

interface VoiceLike { name: string; lang: string; localService: boolean }

/** Novelty voices that ship with macOS. Never pick these to read a briefing. */
const NOVELTY = /^(albert|bad news|bahh|bells|boing|bubbles|cellos|deranged|good news|hysterical|jester|organ|pipe organ|superstar|trinoids|whisper|wobble|zarvox|fred|junior|ralph|kathy|eddy|flo|grandma|grandpa|reed|rocko|sandy|shelley)\b/i
const LIKED = /^(daniel|serena|oliver|kate|arthur|martha|samantha|george|hazel|susan|ryan|libby)\b/i

/** Keep only voices that run on this device (never cloud/"Online" voices), best first. */
export function pickLocalVoice<T extends VoiceLike>(voices: T[]): T | null {
  const local = voices.filter((v) => v.localService && !/online|natural|cloud/i.test(v.name) && !NOVELTY.test(v.name))
  const score = (v: T) =>
    (/premium/i.test(v.name) ? 30 : /enhanced/i.test(v.name) ? 20 : 0) +
    (/^en[-_]GB/i.test(v.lang) ? 10 : /^en/i.test(v.lang) ? 5 : -100) +
    (LIKED.test(v.name) ? 3 : 0)
  const best = [...local].sort((a, b) => score(b) - score(a))[0]
  return best && score(best) > 0 ? best : null
}

let ctx: AudioContext | null = null
let source: AudioBufferSourceNode | null = null

/** Call straight from a click: browsers only allow audio after a user action. */
export function unlockAudio(sampleRate = 22050): void {
  try {
    ctx = ctx ?? new AudioContext({ sampleRate })
    void ctx.resume()
  } catch {
    /* no audio device: reported when playback is attempted */
  }
}

/** Convert raw 16-bit little-endian mono PCM to floats in [-1, 1]. */
export function pcmToFloat(buf: ArrayBuffer): Float32Array {
  const n = Math.floor(buf.byteLength / 2)
  const view = new DataView(buf)
  const out = new Float32Array(n)
  for (let i = 0; i < n; i++) out[i] = view.getInt16(i * 2, true) / 32768
  return out
}

export async function speakWithPiper(parts: string[], sampleRate: number, onEnd: () => void): Promise<void> {
  const pcm = await api.speakPiper(parts)
  const data = pcmToFloat(pcm)
  if (data.length < 1000) throw 'The voice engine returned no audio.'
  ctx = ctx ?? new AudioContext({ sampleRate })
  await ctx.resume()
  if (ctx.state !== 'running') throw 'Windows blocked audio playback. Click Listen again.'
  const buffer = ctx.createBuffer(1, data.length, sampleRate)
  buffer.copyToChannel(data as Float32Array<ArrayBuffer>, 0)
  stopPiper()
  source = ctx.createBufferSource()
  source.buffer = buffer
  source.connect(ctx.destination)
  source.onended = onEnd
  source.start()
}

function stopPiper(): void {
  if (source) {
    source.onended = null
    try { source.stop() } catch { /* already stopped */ }
    source = null
  }
}

/** Windows loads its voice list a moment after start, so wait briefly for it. */
function voicesReady(): Promise<SpeechSynthesisVoice[]> {
  const now = window.speechSynthesis.getVoices()
  if (now.length) return Promise.resolve(now)
  return new Promise((resolve) => {
    const done = () => resolve(window.speechSynthesis.getVoices())
    window.speechSynthesis.addEventListener('voiceschanged', done, { once: true })
    window.setTimeout(done, 1500)
  })
}

/** Returns the voice name used, or null when no private voice is available. */
export async function speakSystem(parts: string[], onEnd: () => void): Promise<string | null> {
  if (!canListen()) return null
  const voice = pickLocalVoice(await voicesReady())
  if (!voice) return null
  window.speechSynthesis.cancel()
  parts.forEach((text, i) => {
    const u = new SpeechSynthesisUtterance(text)
    u.voice = voice
    u.lang = voice.lang
    if (i === parts.length - 1) u.onend = onEnd
    u.onerror = onEnd
    window.speechSynthesis.speak(u)
  })
  return voice.name
}

export function stopSpeaking(): void {
  stopPiper()
  if (canListen()) window.speechSynthesis.cancel()
}

export interface PlayResult { ok: boolean; message: string }

/** Read lines aloud with the best private voice available, and say what happened. */
export async function playParts(parts: string[], onEnd: () => void): Promise<PlayResult> {
  let piperProblem = ''
  try {
    const v = await api.voiceStatus()
    if (v.installed) {
      await speakWithPiper(parts, v.sample_rate, onEnd)
      return { ok: true, message: 'Playing with the natural voice (Alan).' }
    }
  } catch (e) {
    piperProblem = typeof e === 'string' ? e : 'The natural voice could not play.'
  }
  const name = await speakSystem(parts, onEnd)
  if (name) return { ok: true, message: `${piperProblem ? piperProblem + ' ' : ''}Playing with the built-in voice: ${name}.` }
  return {
    ok: false,
    message: piperProblem || 'No private voice found. Install the natural voice in Settings → Voice.',
  }
}
