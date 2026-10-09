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

export function briefScript(stories: Story[]): string[] {
  const parts = [`Your sitrep. ${stories.length} things worth knowing today.`]
  stories.forEach((s, i) => {
    parts.push(`Story ${i + 1}. ${s.headline}. ${s.tldr} Why it matters: ${s.why}`)
  })
  parts.push("That's it for today.")
  return parts
}

interface VoiceLike { name: string; lang: string; localService: boolean }

/** Keep only voices that run on this device (never cloud/"Online" voices). */
export function pickLocalVoice<T extends VoiceLike>(voices: T[]): T | null {
  const local = voices.filter((v) => v.localService && !/online|natural|cloud/i.test(v.name))
  return (
    local.find((v) => /^en[-_]GB/i.test(v.lang)) ??
    local.find((v) => /^en/i.test(v.lang)) ??
    null
  )
}

let ctx: AudioContext | null = null
let source: AudioBufferSourceNode | null = null

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
  ctx = ctx ?? new AudioContext({ sampleRate })
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

/** Returns false when no private voice is available. */
export function speakSystem(parts: string[], onEnd: () => void): boolean {
  if (!canListen()) return false
  const voice = pickLocalVoice(window.speechSynthesis.getVoices())
  if (!voice) return false
  window.speechSynthesis.cancel()
  parts.forEach((text, i) => {
    const u = new SpeechSynthesisUtterance(text)
    u.voice = voice as SpeechSynthesisVoice
    u.lang = voice.lang
    if (i === parts.length - 1) u.onend = onEnd
    window.speechSynthesis.speak(u)
  })
  return true
}

export function stopSpeaking(): void {
  stopPiper()
  if (canListen()) window.speechSynthesis.cancel()
}

/** Read lines aloud with the best private voice available. Resolves false if none. */
export async function playParts(parts: string[], onEnd: () => void): Promise<boolean> {
  try {
    const v = await api.voiceStatus()
    if (v.installed) {
      await speakWithPiper(parts, v.sample_rate, onEnd)
      return true
    }
  } catch {
    // fall through to an on-device system voice
  }
  return speakSystem(parts, onEnd)
}
