// Listen mode uses the operating system's built-in text-to-speech
// (Windows/macOS voices). It works offline and sends nothing anywhere.
import type { Story } from './api'

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

export function speak(parts: string[], onEnd: () => void): void {
  if (!canListen()) return
  window.speechSynthesis.cancel()
  parts.forEach((text, i) => {
    const u = new SpeechSynthesisUtterance(text)
    u.rate = 1.0
    u.lang = 'en-GB'
    if (i === parts.length - 1) u.onend = onEnd
    window.speechSynthesis.speak(u)
  })
}

export function stopSpeaking(): void {
  if (canListen()) window.speechSynthesis.cancel()
}
